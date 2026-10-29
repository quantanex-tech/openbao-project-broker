import hashlib
import io
import json
import logging
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import broker
import google_client as gc
import google_migration as gm
import workspace_google as wg
from generic_api import ApiError


def record():
    c={'version':1,'account':'source@example.test','capabilities':['drive.read'],
       'scopes':sorted(gm.BASE_SCOPES|{gm.SCOPE+'drive'})}
    g={'type':'authorized_user','account_email':c['account'],
       'token_uri':'https://oauth2.googleapis.com/token','scopes':c['scopes'],
       'client_id':'fixture.apps.googleusercontent.com','client_secret':'fixture-secret',
       'refresh_token':'fixture-refresh'}
    return {'_google_migration':c,'authorized_user_json':g}


class DownloadRoutes(unittest.TestCase):
    def setUp(self):self.config=gm.profile(record())[0]
    def denied(self,operation,params,size=0):
        with self.assertRaises(ApiError):gm.route(self.config,operation,params,size)
    def test_media_download_is_fixed_get_without_caller_query_controls(self):
        method,url,headers,limit=gm.route(self.config,'drive_file_download',{'fileId':'abc_123-'},0)
        parsed=urlsplit(url)
        self.assertEqual((method,parsed.scheme,parsed.netloc,parsed.path),
                         ('GET','https','www.googleapis.com','/drive/v3/files/abc_123-'))
        self.assertEqual(parse_qs(parsed.query),{'alt':['media'],'supportsAllDrives':['true']})
        self.assertEqual(headers,{});self.assertEqual(limit,32*1024*1024)
    def test_export_is_fixed_route_with_only_whitelisted_formats(self):
        for mime in wg.DRIVE_EXPORT_MIME_TYPES:
            method,url,headers,limit=gm.route(self.config,'drive_file_export',{'fileId':'abc','mimeType':mime},0)
            parsed=urlsplit(url)
            self.assertEqual((method,parsed.netloc,parsed.path),('GET','www.googleapis.com','/drive/v3/files/abc/export'))
            self.assertEqual(parse_qs(parsed.query),{'mimeType':[mime]})
            self.assertEqual(headers,{});self.assertEqual(limit,10*1024*1024)
    def test_invalid_missing_or_unallocated_export_formats_are_denied(self):
        for mime in (None,'text/html','text/csv','application/zip','application/json','https://evil.example',['application/pdf'],'application/pdf\r\nX: bad'):
            self.denied('drive_file_export',{'fileId':'abc','mimeType':mime})
        self.denied('drive_file_export',{'fileId':'abc'})
    def test_caller_cannot_set_url_range_headers_abuse_or_alt(self):
        for operation,base in [('drive_file_download',{'fileId':'abc'}),('drive_file_export',{'fileId':'abc','mimeType':'application/pdf'})]:
            for extra in ({'url':'https://evil.example'},{'downloadUrl':'https://evil.example'},
                          {'headers':{'Range':'bytes=0-1'}},{'Range':'bytes=0-1'},
                          {'acknowledgeAbuse':True},{'alt':'json'},{'supportsAllDrives':False},
                          {'exportOptions':{}},{'access_token':'fixture'}):
                with self.subTest(operation=operation,extra=extra):self.denied(operation,{**base,**extra})
    def test_read_body_and_invalid_ids_are_denied(self):
        for operation in ('drive_file_download','drive_file_export'):
            base={'mimeType':'application/pdf'} if operation.endswith('export') else {}
            for value in (None,'','../x','abc?alt=media','abc%2fother','https://evil.example','abc\r\nX: bad'):
                self.denied(operation,{**base,'fileId':value})
            self.denied(operation,{**base,'fileId':'abc'},1)
    def test_existing_capability_required_and_scopes_unchanged(self):
        for operation,params in [('drive_file_download',{'fileId':'abc'}),('drive_file_export',{'fileId':'abc','mimeType':'application/pdf'})]:
            with self.assertRaises(ApiError):gm.route({'capabilities':['drive.copy']},operation,params,0)
        self.assertEqual(gm.profile(record())[0]['scopes'],sorted(gm.BASE_SCOPES|{gm.SCOPE+'drive'}))


class BinaryResponses(unittest.TestCase):
    def setUp(self):self.proxy=gm.GoogleMigration();self.data=record()
    def test_binary_download_and_export_are_returned_exactly_with_checksum(self):
        payload=b'\x00\xff\xfe\x80%PDF-fixture\r\n'
        for operation,params in [('drive_file_download',{'fileId':'abc'}),('drive_file_export',{'fileId':'abc','mimeType':'application/pdf'})]:
            with patch.object(self.proxy,'token',return_value='fixture-private'),patch.object(gm,'download',return_value=(200,{'content-type':'application/octet-stream'},payload)) as remote:
                metadata,returned=self.proxy.execute(('p','c'),self.data,{'operation':operation,'params':params},b'')
            self.assertEqual(returned,payload);self.assertEqual(metadata['body_bytes'],len(payload))
            self.assertEqual(metadata['sha256'],hashlib.sha256(payload).hexdigest())
            self.assertEqual(remote.call_count,1)
            self.assertEqual(remote.call_args.args[1],'GET')
    def test_nonbinary_metadata_operations_still_require_json_object(self):
        with patch.object(self.proxy,'token',return_value='fixture-private'),patch.object(gm,'download',return_value=(200,{},b'\x00\xffnot-json')):
            with self.assertRaises(ApiError) as error:self.proxy.execute(('p','c'),self.data,{'operation':'drive_file_get','params':{'fileId':'abc'}},b'')
        self.assertEqual(error.exception.code,'google_response_invalid')
    def test_failed_download_is_not_automatically_retried(self):
        with patch.object(self.proxy,'token',return_value='fixture-private'),patch.object(gm,'download',side_effect=ApiError('google_transport_uncertain','safe')) as remote:
            with self.assertRaises(ApiError):self.proxy.execute(('p','c'),self.data,{'operation':'drive_file_download','params':{'fileId':'abc'}},b'')
        self.assertEqual(remote.call_count,1)
    def test_https_reader_enforces_the_route_response_bound(self):
        class Response:
            status=200
            def getheader(self,key,default=None):return default
            def read(self,n):return b'x'*n
        class Connection:
            def __init__(self,*args):pass
            def request(self,*args):pass
            def getresponse(self):return Response()
            def close(self):pass
        for operation,params in [('drive_file_download',{'fileId':'abc'}),('drive_file_export',{'fileId':'abc','mimeType':'application/pdf'})]:
            method,url,headers,limit=gm.route(gm.profile(self.data)[0],operation,params,0)
            with patch.object(gm,'public_addresses',return_value=['203.0.113.10']),patch.object(gm,'PinnedHTTPS',Connection):
                with self.assertRaises(ApiError) as error:gm.download(url,method,headers,b'',limit)
            self.assertEqual(error.exception.code,'google_response_too_large')


class BinarySocketTransport(unittest.TestCase):
    def test_binary_export_survives_the_existing_private_transfer_protocol(self):
        with tempfile.TemporaryDirectory() as td:
            path=str(Path(td)/'socket');audit=io.StringIO()
            logger=logging.Logger('drive-download-test');logger.addHandler(logging.StreamHandler(audit))
            service=broker.Broker('unused-config.json',{},logger);data=record()
            service.project=lambda uid,req:('p',{'secret_prefix':'projects/p'},None)
            service.read=lambda *args:{'data':data}
            server=broker.Server(path,broker.Handler);server.broker=service
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                payload=b'PK\x03\x04\x00\xffbinary-presentation'
                with patch.object(service.google,'token',return_value='fixture-private'),patch.object(gm,'download',return_value=(200,{},payload)):
                    metadata,returned=gc.call('p','c','drive_file_export',{'fileId':'abc','mimeType':'application/vnd.openxmlformats-officedocument.presentationml.presentation'},socket_path=path)
                self.assertEqual(returned,payload);self.assertEqual(metadata['sha256'],hashlib.sha256(payload).hexdigest())
                self.assertNotIn('fixture-private',audit.getvalue());self.assertNotIn('binary-presentation',audit.getvalue())
            finally:server.shutdown();server.server_close();thread.join(3)


if __name__=='__main__':unittest.main()

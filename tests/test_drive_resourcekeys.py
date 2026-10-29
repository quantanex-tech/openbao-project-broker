import hashlib
import io
import json
import logging
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs,urlsplit

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import broker
import google_client as gc
import google_migration as gm
from generic_api import ApiError
from test_drive_downloads import record

FIXTURE_KEY='0-PRIVATE_fixtureResourceKey'


class ResourceKeys(unittest.TestCase):
    def setUp(self):self.config=gm.profile(record())[0]
    def test_key_is_one_same_file_header_never_a_query_parameter(self):
        operations=[('drive_file_get',{'fields':'id,size,md5Checksum'}),
                    ('drive_file_download',{}),('drive_file_export',{'mimeType':'application/pdf'})]
        for op,params in operations:
            method,url,headers,limit=gm.route(self.config,op,{'fileId':'same_file-123','resourceKey':FIXTURE_KEY,**params},0)
            self.assertEqual(method,'GET');self.assertEqual(urlsplit(url).hostname,'www.googleapis.com')
            self.assertEqual(headers,{'X-Goog-Drive-Resource-Keys':'same_file-123/'+FIXTURE_KEY})
            self.assertNotIn(FIXTURE_KEY,url);self.assertNotIn('resourceKey',parse_qs(urlsplit(url).query))
            self.assertIn('/files/same_file-123',urlsplit(url).path)
            self.assertEqual(limit,(10 if op=='drive_file_export' else 32)*1024*1024)
    def test_absent_key_preserves_existing_routes(self):
        for op,params in [('drive_file_get',{}),('drive_file_download',{}),('drive_file_export',{'mimeType':'application/pdf'})]:
            self.assertEqual(gm.route(self.config,op,{'fileId':'abc',**params},0)[2],{})
    def test_key_cannot_inject_headers_ids_pairs_queries_or_urls(self):
        invalid=(None,True,123,[],{},'',',other/key','key,other/key','other/key',
                 '../key','https://evil.example','key?x=y','key%2fother','key value',
                 'key\r\nAuthorization: attacker','key\x00value','x'*257)
        for key in invalid:
            for op,params in [('drive_file_get',{}),('drive_file_download',{}),('drive_file_export',{'mimeType':'application/pdf'})]:
                with self.subTest(operation=op,key_type=type(key).__name__),self.assertRaises(ApiError):
                    gm.route(self.config,op,{'fileId':'abc','resourceKey':key,**params},0)
    def test_file_id_still_validated_before_header_assembly(self):
        for fid in (None,[],True,'abc,other','abc/key','abc\r\nX: injected'):
            with self.assertRaises(ApiError):gm.route(self.config,'drive_file_download',{'fileId':fid,'resourceKey':FIXTURE_KEY},0)
    def test_resource_key_not_allocated_to_mutations_or_other_reads(self):
        for op,params,size in [('drive_file_copy',{'fileId':'abc'},2),('drive_share',{'fileId':'abc'},2),
                               ('drive_permissions_list',{'fileId':'abc'},0),('drive_files_list',{},0),
                               ('calendar_get',{'calendarId':'primary'},0),('identity',{},0)]:
            config={**self.config,'capabilities':['drive.read','drive.copy','drive.share','calendar.read']}
            with self.assertRaises(ApiError):gm.route(config,op,{**params,'resourceKey':FIXTURE_KEY},size)
    def test_resource_key_cannot_supply_missing_capability(self):
        with self.assertRaises(ApiError):gm.route({'capabilities':['drive.copy']},'drive_file_download',{'fileId':'abc','resourceKey':FIXTURE_KEY},0)
    def test_export_size_label_is_fixed_and_provider_text_stays_private(self):
        result=gm.safe_rejection(json.dumps({'error':{'message':FIXTURE_KEY+' private@example.test is too large',
              'errors':[{'reason':'exportSizeLimitExceeded','message':'PRIVATE-file-name'}]}}).encode())
        self.assertIn('exportSizeLimitExceeded',result)
        for private in (FIXTURE_KEY,'private@example.test','PRIVATE-file-name'):self.assertNotIn(private,result)
        other=gm.safe_rejection(json.dumps({'error':{'message':'exportSizeLimitExceeded '+FIXTURE_KEY,
              'errors':[{'reason':'PRIVATE-file-name'}]}}).encode())
        self.assertNotIn('exportSizeLimitExceeded',other);self.assertNotIn(FIXTURE_KEY,other)


class ResourceKeyAudit(unittest.TestCase):
    def test_private_key_not_returned_or_logged_on_success_or_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            path=str(Path(td)/'socket');audit=io.StringIO()
            logger=logging.Logger('resource-key-test');logger.addHandler(logging.StreamHandler(audit))
            service=broker.Broker('unused-config.json',{},logger);data=record()
            service.project=lambda uid,req:('p',{'secret_prefix':'projects/p'},None)
            service.read=lambda *args:{'data':data}
            server=broker.Server(path,broker.Handler);server.broker=service
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                payload=b'\x00image-fixture\xff'
                def allowed(url,method,headers,body,limit):
                    self.assertEqual(headers['X-Goog-Drive-Resource-Keys'],'abc/'+FIXTURE_KEY)
                    self.assertNotIn(FIXTURE_KEY,url)
                    return 200,{},payload
                with patch.object(service.google,'token',return_value='fixture-private'),patch.object(gm,'download',side_effect=allowed):
                    metadata,returned=gc.call('p','c','drive_file_download',{'fileId':'abc','resourceKey':FIXTURE_KEY},socket_path=path)
                self.assertEqual(returned,payload);self.assertEqual(metadata['sha256'],hashlib.sha256(payload).hexdigest())
                with patch.object(service.google,'token',return_value='fixture-private'),patch.object(gm,'download',side_effect=ApiError('google_upstream_rejected','Google rejected the read.',404)):
                    with self.assertRaises(gc.GoogleError) as failure:gc.call('p','c','drive_file_get',{'fileId':'abc','resourceKey':FIXTURE_KEY},socket_path=path)
                self.assertNotIn(FIXTURE_KEY,json.dumps(failure.exception.error))
                self.assertNotIn(FIXTURE_KEY,json.dumps(metadata));self.assertNotIn(FIXTURE_KEY,audit.getvalue())
                self.assertNotIn('X-Goog-Drive-Resource-Keys',audit.getvalue())
            finally:server.shutdown();server.server_close();thread.join(3)


if __name__=='__main__':unittest.main()

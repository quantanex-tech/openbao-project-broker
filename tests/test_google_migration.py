import base64
import copy
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

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import broker
import generic_api
import google_client as gc
import google_migration as gm


def record(caps=('gmail.read','gmail.import','gmail.labels.create','gmail.drafts.create')):
    config={'version':1,'account':'operator@example.test','capabilities':list(caps),'scopes':sorted(gm.BASE_SCOPES|set().union(*(gm.CAP_SCOPES[c] for c in caps)))}
    if 'storage.read' in caps: config['bucket']='dwt-takeout-export--123456'
    grant={'type':'authorized_user','account_email':config['account'],'token_uri':'https://oauth2.googleapis.com/token','scopes':config['scopes'],'client_id':'client.example','client_secret':'PRIVATE-CLIENT-SECRET','refresh_token':'PRIVATE-REFRESH-TOKEN'}
    return {'_google_migration':config,'authorized_user_json':json.dumps(grant)}


def oauth(data):
    return [(200,{'access_token':'ya29.PRIVATE-ACCESS-TOKEN','expires_in':3600,'token_type':'Bearer','scope':' '.join(data['_google_migration']['scopes'])}),(200,{'email':'operator@example.test','email_verified':True,'sub':'123'})]


class Profiles(unittest.TestCase):
    def test_existing_generic_profile_unchanged(self):
        data={'api_token':'fake-key','_http':{'version':1,'base_url':'https://api.figma.com','paths':['/v1/me'],'methods':['GET'],'auth':{'type':'header','field':'api_token','name':'X-Figma-Token'}}}
        self.assertEqual(generic_api.ApiProxy().describe(data)['status'],'ready')
        self.assertEqual(gm.describe(data)['status'],'not_configured')

    def test_no_credential_catalog_disclosure(self):
        data=record(); result=gm.describe(data)
        self.assertEqual(result['status'],'ready')
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertNotIn('authorized_user_json',result)

    def test_invalid_profiles(self):
        original=record()
        for field,value in [('account','other@example.com'),('capabilities',['gmail.send']),('scopes',list(gm.BASE_SCOPES)),('bucket','other-bucket'),('token_url','https://evil.example')]:
            with self.subTest(field=field):
                data=copy.deepcopy(original);data['_google_migration'][field]=value
                self.assertEqual(gm.describe(data)['status'],'invalid_configuration')

    def test_bad_grant_endpoint(self):
        data=record();grant=json.loads(data['authorized_user_json']);grant['token_uri']='https://evil.example/token';data['authorized_user_json']=json.dumps(grant)
        self.assertEqual(gm.describe(data)['status'],'invalid_configuration')

    def test_source_write_denied(self):
        config,_=gm.profile(record(('gmail.read',)))
        for op in ['gmail_import','gmail_draft_create','gmail_label_create']:
            with self.subTest(operation=op),self.assertRaises(gm.ApiError): gm.route(config,op,{},10)

    def test_send_delete_arbitrary_url_denied(self):
        config,_=gm.profile(record())
        for op in ['gmail_send','gmail_delete','https://evil.example','refresh_token','gmail_message_get/send']:
            with self.subTest(operation=op),self.assertRaises(gm.ApiError):gm.route(config,op,{},0)
        for params in [{'id':'123/../send'},{'id':'123','url':'https://evil.example'},{'id':'123','access_token':'x'},{'id':'123','userId':'other@example.com'}]:
            with self.subTest(params=params),self.assertRaises(gm.ApiError):gm.route(config,'gmail_message_get',params,0)

    def test_body_limit_and_read_bodies(self):
        config,_=gm.profile(record())
        for n in [-1,True,gm.MAX_BODY+1]:
            with self.subTest(n=n),self.assertRaises(gm.ApiError):gm.route(config,'gmail_import',{},n)
        with self.assertRaises(gm.ApiError):gm.route(config,'gmail_profile',{},10)

    def test_import_no_calendar_side_effect(self):
        config,_=gm.profile(record())
        with self.assertRaises(gm.ApiError):gm.route(config,'gmail_import',{'processForCalendar':True},10)
        self.assertIn('processForCalendar=false',gm.route(config,'gmail_import',{},10)[1])

    def test_bucket_pin_and_name_escaping(self):
        config,_=gm.profile(record(('storage.read',)))
        params={'object':'folder/Status report.html','generation':'123','offset':0,'length':100}
        method,url,headers,limit=gm.route(config,'storage_download',params,0)
        self.assertIn('/dwt-takeout-export--123456/o/folder%2FStatus%20report.html',url)
        self.assertIn('ifGenerationMatch=123',url)
        self.assertEqual(headers['Range'],'bytes=0-99')
        for extra in [{'bucket':'evil'},{'generation':'x'},{'length':gm.MAX_CHUNK+1},{'offset':-1}]:
            with self.subTest(extra=extra),self.assertRaises(gm.ApiError):gm.route(config,'storage_download',{**params,**extra},0)

    def test_body_schema_rejects_arbitrary_send_fields(self):
        for value in [{'raw':'aGVsbG8=','url':'https://evil.example'},{'raw':'!bad'},{'raw':'aGVsbG8=','labelIds':['bad/label']},{'raw':'aGVsbG8=','threadId':'x'}]:
            with self.subTest(value=value),self.assertRaises(gm.ApiError):gm.validate_body('gmail_import',json.dumps(value).encode())
        gm.validate_body('gmail_import',b'{"raw":"aGVsbG8=","labelIds":["Label_1"]}')
        gm.validate_body('gmail_draft_create',b'{"message":{"raw":"aGVsbG8="}}')


class OAuth(unittest.TestCase):
    def setUp(self):
        self.data=record();self.config,self.grant=gm.profile(self.data);self.proxy=gm.GoogleMigration()

    def test_refresh_cached_and_identity_verified(self):
        with patch.object(gm,'exchange',side_effect=oauth(self.data)) as remote:
            first=self.proxy.token(('project','grant'),self.data,self.config,self.grant)
            second=self.proxy.token(('project','grant'),self.data,self.config,self.grant)
        self.assertEqual(first,second);self.assertEqual(remote.call_count,2)
        self.assertEqual(remote.call_args_list[0].args[0],'https://oauth2.googleapis.com/token')
        self.assertIn(b'grant_type=refresh_token',remote.call_args_list[0].args[3])

    def test_cache_invalidated_on_record_change(self):
        with patch.object(gm,'exchange',side_effect=oauth(self.data)*2) as remote:
            self.proxy.token(('p','c'),self.data,self.config,self.grant)
            self.proxy.token(('p','c'),{**self.data,'purpose':'changed'},self.config,self.grant)
        self.assertEqual(remote.call_count,4)

    def test_wrong_account_and_scope_denied(self):
        for change in ['account','scope','rotation']:
            seq=oauth(self.data)
            if change=='account':seq[1][1]['email']='other@example.com'
            if change=='scope':seq[0][1]['scope']='openid'
            if change=='rotation':seq[0][1]['refresh_token']='NEW-PRIVATE'
            with self.subTest(change=change),patch.object(gm,'exchange',side_effect=seq),self.assertRaises(gm.ApiError):
                self.proxy.token(('p','c'),self.data,self.config,self.grant)

    def test_refresh_failure_does_not_expose_response(self):
        with patch.object(gm,'exchange',return_value=(400,{'error':'PRIVATE-REFRESH-TOKEN'})):
            with self.assertRaises(gm.ApiError) as error:self.proxy.token(('p','c'),self.data,self.config,self.grant)
        self.assertNotIn('PRIVATE',str(error.exception))

    def test_write_not_retried(self):
        request={'action':'google_transfer','operation':'gmail_import','params':{}}
        with patch.object(self.proxy,'token',return_value='private'),patch.object(gm,'download',side_effect=gm.ApiError('failed','safe',401)) as remote:
            with self.assertRaises(gm.ApiError):self.proxy.execute(('p','c'),self.data,request,b'{"raw":"aGVsbG8="}')
        self.assertEqual(remote.call_count,1)

    def test_range_mismatch_rejected(self):
        data=record(('storage.read',));request={'operation':'storage_download','params':{'object':'x','generation':'123','offset':4,'length':3}}
        with patch.object(self.proxy,'token',return_value='private'),patch.object(gm,'download',return_value=(206,{'content-range':'bytes 0-2/7'},b'abc')):
            with self.assertRaises(gm.ApiError):self.proxy.execute(('p','c'),data,request,b'')


class Transport(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=str(Path(self.tmp.name)/'sock')
        self.audit=io.StringIO();logger=logging.Logger('test');logger.addHandler(logging.StreamHandler(self.audit))
        self.broker=broker.Broker('unused-config.json',{},logger)
        self.data=record()
        self.broker.project=lambda uid,req: ('p',{'secret_prefix':'projects/p'},None)
        self.broker.read=lambda *args:{'data':self.data}
        self.server=broker.Server(self.path,broker.Handler);self.server.broker=self.broker
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.tmp.cleanup()

    def test_large_exact_bytes_over_socket(self):
        payload=json.dumps({'raw':base64.urlsafe_b64encode(b'x'*(45*1024*1024)).decode()}).encode()
        def respond(identity,data,request,body):
            self.assertEqual(body,payload)
            return {'http_status':200,'body_bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest()},payload
        with patch.object(self.broker.google,'token',return_value='private'), patch.object(gm,'download',return_value=(200,{},payload)) as remote:
            metadata,result=gc.call('p','c','gmail_import',{},payload,self.path)
        self.assertEqual(remote.call_count,1)
        self.assertEqual(result,payload)
        self.assertEqual(metadata['body_bytes'],len(payload))
        self.assertNotIn('raw',self.audit.getvalue());self.assertNotIn('PRIVATE',self.audit.getvalue())

    def test_denied_uid_before_upload(self):
        def reject(*args):raise broker.BrokerError('project_access_denied','Denied')
        self.broker.project=reject
        with patch.object(self.broker.google,'execute') as remote,self.assertRaises(gc.GoogleError) as error:
            gc.call('p','c','gmail_profile',socket_path=self.path)
        self.assertEqual(error.exception.error['code'],'project_access_denied');remote.assert_not_called()

    def test_busy_does_not_execute(self):
        self.broker.google.transfer_slot.acquire()
        try:
            with patch.object(self.broker.google,'execute') as remote,self.assertRaises(gc.GoogleError) as error:
                gc.call('p','c','gmail_profile',socket_path=self.path)
            self.assertEqual(error.exception.error['code'],'google_busy');remote.assert_not_called()
        finally:self.broker.google.transfer_slot.release()

    def test_partial_upload_never_executes(self):
        request={'action':'google_transfer','project':'p','credential':'c','operation':'gmail_import','params':{},'body_bytes':100}
        with patch.object(self.broker.google,'execute') as remote:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.connect(self.path);connection.sendall(json.dumps(request).encode()+b'\n')
                stream=connection.makefile('rb');self.assertTrue(json.loads(stream.readline())['ready'])
                connection.sendall(b'partial');connection.shutdown(socket.SHUT_WR)
                error=json.loads(stream.readline());stream.close()
            self.assertEqual(error['error']['code'],'google_body_incomplete');remote.assert_not_called()

    def test_client_rejects_corrupted_result(self):
        with patch.object(self.broker.google,'execute',return_value=({'http_status':200,'body_bytes':2,'sha256':'bad'},b'{}')):
            with self.assertRaises(gc.GoogleError):gc.call('p','c','gmail_profile',socket_path=self.path)


if __name__=='__main__':unittest.main(verbosity=2)

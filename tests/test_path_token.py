import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import generic_api as api

TOKEN='fixture_private_token-123'
ROUTE='/api/webhooks/123456789/{credential}'
def record():
    return {'webhook_token':TOKEN,'_http':{'version':1,'base_url':'https://discord.com','paths':[ROUTE],'methods':['POST'],'auth':{'type':'path_token','field':'webhook_token'}}}

class PathToken(unittest.TestCase):
    def setUp(self):self.proxy=api.ApiProxy()
    def request(self,**kwargs):
        return self.proxy.request(('infrastructure','migration/discord-alerts'),record(),{'method':'POST','path':ROUTE,**kwargs})
    def test_injected_only_inside_transport_and_response_redacted(self):
        with patch.object(api,'exchange',return_value=(200,{'id':'42','echo':TOKEN,'token':TOKEN})) as http:
            result=self.request(query={'wait':'true'},json_body={'content':'Test','allowed_mentions':{'parse':[]}})
        url,method,headers,body=http.call_args.args
        self.assertEqual(url,'https://discord.com/api/webhooks/123456789/'+TOKEN+'?wait=true')
        self.assertEqual(method,'POST');self.assertNotIn(TOKEN,json.dumps(headers));self.assertNotIn(TOKEN,body.decode())
        self.assertEqual(result['data']['echo'],'[REDACTED]');self.assertNotIn(TOKEN,json.dumps(result))
    def test_catalog_is_nonsecret(self):
        result=self.proxy.describe(record())
        self.assertEqual(result['status'],'ready');self.assertEqual(result['paths'],[ROUTE]);self.assertNotIn(TOKEN,json.dumps(result))
    def test_encoded_placeholder_is_canonicalized_before_injection(self):
        with patch.object(api,'exchange',return_value=(200,{'id':'42'})) as http:
            self.request(path=ROUTE.replace('{','%7B').replace('}','%7D'))
        self.assertTrue(http.call_args.args[0].endswith('/'+TOKEN))
    def test_methods_and_adjacent_routes_denied_before_transport(self):
        with patch.object(api,'exchange') as http:
            for route,method in [(ROUTE,'GET'),(ROUTE,'DELETE'),(ROUTE+'/messages/42','POST'),(ROUTE.replace('{credential}',TOKEN),'POST'),('/elsewhere/{credential}','POST')]:
                with self.subTest(route=route,method=method),self.assertRaises(api.ApiError):self.request(path=route,method=method)
            http.assert_not_called()
    def test_traversal_and_url_injection_denied(self):
        with patch.object(api,'exchange') as http:
            for route in ['/../'+ROUTE,ROUTE+'?redirect=evil',ROUTE+'%2f..%2fmessages','https://evil.example/',ROUTE+'\\x']:
                with self.subTest(route=route),self.assertRaises(api.ApiError):self.request(path=route)
            http.assert_not_called()
    def test_profile_requires_one_whole_segment_on_every_exact_route(self):
        for route in ['/api/webhooks/123/','/api/webhooks/123','/x/prefix{credential}','/x/{credential}/{credential}','/x/{other}/{credential}','/x/{credential}/']:
            d=record();d['_http']['paths']=[route]
            with self.subTest(route=route),self.assertRaises(api.ApiError):api.profile(d)
    def test_token_cannot_change_routing_or_query(self):
        for token in ['../other','a/b','a%2Fb','token?x=1','a#fragment','abc.def','a b','a\nheader','x'*513,'']:
            d=record();d['webhook_token']=token
            with self.subTest(token=token),self.assertRaises(api.ApiError):api.profile(d)
    def test_missing_or_extra_auth_configuration_denied(self):
        for change in [{'field':'absent'},{'prefix':'x'},{'field':'_http'}]:
            d=record();d['_http']['auth'].update(change)
            with self.subTest(change=change),self.assertRaises(api.ApiError):api.profile(d)
    def test_http_rejection_not_replayed_and_no_secret_in_error(self):
        with patch.object(api,'exchange',return_value=(429,{'token':TOKEN})) as http:
            with self.assertRaises(api.ApiError) as err:self.request()
        self.assertEqual(http.call_count,1);self.assertEqual(err.exception.status,429);self.assertNotIn(TOKEN,str(err.exception))
    def test_existing_auth_still_works(self):
        for auth in [{'type':'bearer','field':'webhook_token'},{'type':'header','name':'X-API-Key','field':'webhook_token'},{'type':'query','name':'key','field':'webhook_token'},{'type':'none'}]:
            d=record();d['_http'].update(paths=['/v1/example'],auth=auth)
            with self.subTest(auth=auth),patch.object(api,'exchange',return_value=(200,{'value':'ok'})) as http:
                result=self.proxy.request(('p','c'),d,{'method':'POST','path':'/v1/example'})
                self.assertEqual(result['http_status'],200);self.assertEqual(http.call_count,1)

if __name__=='__main__':unittest.main()

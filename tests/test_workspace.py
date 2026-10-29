"""Current Workspace broker boundaries using wholly synthetic in-memory grants."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs,urlsplit

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import google_migration as gm
import workspace_google as wg
from generic_api import ApiError

SOURCE_ACCOUNT='source@example.test'
DESTINATION_ACCOUNT='destination@example.test'


def profile(role):
    """Fabricate independent read/share-source and import-destination fixtures."""
    capabilities={
        'source':['drive.read','drive.share','calendar.read','contacts.read','contacts.other.read'],
        'destination':['drive.read','drive.copy','calendar.read','calendar.import',
                       'contacts.read','contacts.other.read','contacts.create'],
    }[role]
    config={'version':1,'account':SOURCE_ACCOUNT if role=='source' else DESTINATION_ACCOUNT,
            'capabilities':capabilities,'scopes':sorted(gm.BASE_SCOPES|wg.required_scopes(capabilities))}
    if role=='source':config['share_with']=DESTINATION_ACCOUNT
    grant={'type':'authorized_user','client_id':'synthetic-client.apps.googleusercontent.com',
           'client_secret':'SYNTHETIC-CLIENT-SECRET','refresh_token':'SYNTHETIC-REFRESH-TOKEN',
           'account_email':config['account'],'token_uri':'https://oauth2.googleapis.com/token',
           'scopes':list(config['scopes'])}
    return {'_google_migration':config,'authorized_user_json':grant}

class Tests(unittest.TestCase):
    def setUp(self):
        self.source=gm.profile(profile('source'))[0]
        self.dest=gm.profile(profile('destination'))[0]
    def denied(self,fn,*a):
        with self.assertRaises(ApiError):fn(*a)
    def test_profiles_and_scopes(self):
        self.assertEqual(gm.describe(profile('source'))['status'],'ready')
        self.assertEqual(gm.describe(profile('destination'))['status'],'ready')
        d=profile('destination');d['authorized_user_json']['scopes']=[]
        self.denied(gm.profile,d)
    def test_scope_mismatch(self):
        d=profile('source');d['_google_migration']['scopes'].append(gm.SCOPE+'gmail.send')
        self.denied(gm.profile,d)
    def test_identity_mismatch(self):
        d=profile('destination');d['authorized_user_json']['account_email']='wrong@example.test'
        self.denied(gm.profile,d)
    def test_source_cannot_create_or_import(self):
        for op in ['drive_file_copy','drive_folder_create','calendar_create','contact_create']:
            self.denied(gm.route,self.source,op,{},2)
    def test_destination_cannot_share(self):
        self.denied(gm.route,self.dest,'drive_share',{'fileId':'abc'},2)
    def test_no_notifications_or_arbitrary_query(self):
        method,url,_,_=gm.route(self.source,'drive_share',{'fileId':'abc'},2)
        self.assertEqual(method,'POST');self.assertEqual(parse_qs(urlsplit(url).query)['sendNotificationEmail'],['false'])
        self.denied(gm.route,self.source,'drive_share',{'fileId':'abc','sendNotificationEmail':True},2)
    def test_sharing_is_one_reader(self):
        good={'type':'user','role':'reader','emailAddress':DESTINATION_ACCOUNT}
        gm.validate_body('drive_share',json.dumps(good).encode(),self.source)
        for patch in [{'role':'writer'},{'role':'owner'},{'emailAddress':'outside@example.com'},{'type':'anyone'},{'domain':'example.com'}]:
            self.denied(gm.validate_body,'drive_share',json.dumps({**good,**patch}).encode(),self.source)
    def test_share_profile_required(self):
        d=profile('source');del d['_google_migration']['share_with'];self.denied(gm.profile,d)
    def test_no_arbitrary_paths(self):
        for value in ['../permissions','abc?alt=media','https://evil.example','abc%2fdef']:
            self.denied(gm.route,self.source,'drive_file_get',{'fileId':value},0)
    def test_calendar_id_encoded(self):
        _,url,_,_=gm.route(self.source,'calendar_get',{'calendarId':SOURCE_ACCOUNT},0)
        self.assertIn('source%40example.test',url)
        self.denied(gm.route,self.source,'calendar_get',{'calendarId':'../x'},0)
    def test_no_delete_update_or_upload(self):
        for op in ['drive_file_delete','drive_file_update','calendar_event_insert','calendar_event_delete','contact_delete','upload']:
            self.denied(gm.route,self.dest,op,{},2)
    def test_copy_cannot_change_permissions(self):
        gm.validate_body('drive_file_copy',b'{"name":"Copy","parents":["folder"],"appProperties":{"sourceId":"abc"}}',self.dest)
        self.denied(gm.validate_body,'drive_file_copy',b'{"name":"Copy","permissions":[{}]}',self.dest)
    def test_create_only_folder_or_shortcut(self):
        gm.validate_body('drive_folder_create',b'{"name":"Folder","mimeType":"application/vnd.google-apps.folder"}',self.dest)
        self.denied(gm.validate_body,'drive_folder_create',b'{"name":"File","mimeType":"text/plain"}',self.dest)
    def test_calendar_private_import(self):
        _,url,_,_=gm.route(self.dest,'calendar_event_import',{'calendarId':'abc@group.calendar.google.com'},2)
        self.assertTrue(urlsplit(url).path.endswith('/events/import'))
        self.assertNotIn('sendUpdates',url)
        for extra in [{'sendUpdates':'all'},{'conferenceData':{'createRequest':{}}},{'eventType':'outOfOffice'}]:
            self.denied(gm.validate_body,'calendar_event_import',json.dumps({'iCalUID':'abc',**extra}).encode(),self.dest)
    def test_no_contact_members_removed(self):
        gm.validate_body('contact_group_add',b'{"resourceNamesToAdd":["people/c123"]}',self.dest)
        self.denied(gm.validate_body,'contact_group_add',b'{"resourceNamesToRemove":["people/c123"]}',self.dest)
    def test_contact_no_profile_update(self):
        self.denied(gm.validate_body,'contact_create',b'{"resourceName":"people/c123","names":[{}]}',self.dest)
    def test_body_bounds(self):
        self.denied(gm.route,self.dest,'contact_create',{},5*1024*1024)
        self.denied(gm.route,self.dest,'contacts_list',{},1)
    def test_people_repeated_sources_wire_name(self):
        _,url,_,_=gm.route(self.source,'contacts_list',{'personFields':'names','sources':['READ_SOURCE_TYPE_CONTACT']},0)
        q=parse_qs(urlsplit(url).query)
        self.assertEqual(q['sources'],['READ_SOURCE_TYPE_CONTACT']);self.assertNotIn('sources[]',q)
    def test_patch_only_secondary_calendar_with_etag_and_notifications_disabled(self):
        p={'calendarId':'new@group.calendar.google.com','eventId':'event','etag':'"123"'}
        method,url,headers,_=gm.route(self.dest,'calendar_private_event_patch',p,2)
        self.assertEqual(method,'PATCH');self.assertEqual(headers['If-Match'],'"123"')
        self.assertEqual(parse_qs(urlsplit(url).query)['sendUpdates'],['none'])
        for update in [{'calendarId':'primary'},{'etag':'*'},{'etag':'"1"\r\nBad: yes'},{'sendUpdates':'all'}]:
            self.denied(gm.route,self.dest,'calendar_private_event_patch',{**p,**update},2)
        self.denied(gm.route,self.source,'calendar_private_event_patch',p,2)
    def test_patch_body_cannot_cancel_or_invite_or_change_organizer(self):
        gm.validate_body('calendar_private_event_patch',b'{"summary":"Copied exception"}',self.dest)
        for b in [{'status':'cancelled'},{'organizer':{'email':'x@example.test'}},{'conferenceData':{'createRequest':{}}},{'sendUpdates':'all'},{'recurrence':['RRULE:FREQ=DAILY']}]:
            self.denied(gm.validate_body,'calendar_private_event_patch',json.dumps(b).encode(),self.dest)
    def test_patch_requires_private_migration_copy_and_current_etag(self):
        data=profile('destination');proxy=gm.GoogleMigration()
        request={'operation':'calendar_private_event_patch','params':{'calendarId':'new@group.calendar.google.com','eventId':'instance','etag':'"123"'}}
        private={'privateCopy':True,'etag':'"123"','extendedProperties':{'private':{'migrationSourceId':'source','migrationSourceCalendar':'original'}}}
        for patch_fields in [{'privateCopy':False},{'etag':'"old"'},{'extendedProperties':{}}]:
            with patch.object(proxy,'token',return_value='private'),patch.object(gm,'download',return_value=(200,{},json.dumps({**private,**patch_fields}).encode())) as remote:
                self.denied(proxy.execute,('p','c'),data,request,b'{"summary":"Copy"}')
                self.assertEqual(remote.call_count,1)
        with patch.object(proxy,'token',return_value='private'),patch.object(gm,'download',side_effect=[(200,{},json.dumps(private).encode()),(200,{},b'{"id":"instance"}')]) as remote:
            proxy.execute(('p','c'),data,request,b'{"summary":"Copy"}')
            self.assertEqual(remote.call_count,2)
            self.assertEqual(remote.call_args_list[1].args[1],'PATCH')
            self.assertEqual(remote.call_args_list[1].args[2]['If-Match'],'"123"')
    def test_safe_errors_never_return_free_text_or_secret_values(self):
        sample={'error':{'message':'Invalid organizer email SECRET-ACCESS-TOKEN at private@example.test','errors':[{'reason':'badRequest','message':'PRIVATE-REFRESH-TOKEN'}]}}
        result=gm.safe_rejection(json.dumps(sample).encode())
        self.assertIn('badRequest',result);self.assertIn('organizer',result)
        for value in ['SECRET','PRIVATE','example','TOKEN']:self.assertNotIn(value,result)
        self.assertNotIn('PRIVATE',gm.safe_rejection(b'{"error":{"errors":[{"reason":"PRIVATE-REFRESH-TOKEN"}]}}'))
        for malformed in (b'not json',b'{"error":null}',b'{"error":{"errors":null}}'):
            self.assertEqual(gm.safe_rejection(malformed),'')

    def test_owner_configured_calendar_markers_preserve_copy_guards(self):
        data=profile('destination')
        data['_google_migration']['calendar_markers']={'source_id':'sourceEventId','source_calendar':'sourceCalendarId'}
        proxy=gm.GoogleMigration()
        request={'operation':'calendar_private_event_patch','params':{'calendarId':'new@group.calendar.google.com','eventId':'instance','etag':'"123"'}}
        event={'privateCopy':True,'etag':'"123"','extendedProperties':{'private':{'sourceEventId':'source','sourceCalendarId':'original'}}}
        with patch.object(proxy,'token',return_value='fixture'), patch.object(gm,'download',side_effect=[(200,{},json.dumps(event).encode()),(200,{},b'{}')]) as remote:
            proxy.execute(('p','c'),data,request,b'{"summary":"Copy"}')
            self.assertEqual(remote.call_count,2)
        del event['extendedProperties']['private']['sourceCalendarId']
        with patch.object(proxy,'token',return_value='fixture'), patch.object(gm,'download',return_value=(200,{},json.dumps(event).encode())) as remote:
            self.denied(proxy.execute,('p','c'),data,request,b'{"summary":"Copy"}')
            self.assertEqual(remote.call_count,1)

    def test_calendar_marker_configuration_cannot_relax_required_pair(self):
        for markers in ({}, {'source_id':'id'}, {'source_id':'id','source_calendar':'id'},
                        {'source_id':'id','source_calendar':'bad/key'}):
            data=profile('destination');data['_google_migration']['calendar_markers']=markers
            self.denied(gm.profile,data)
        data=profile('source')
        data['_google_migration']['calendar_markers']={'source_id':'event','source_calendar':'calendar'}
        self.denied(gm.profile,data)
    def test_existing_mail_profile_unchanged(self):
        c={'version':1,'account':DESTINATION_ACCOUNT,'capabilities':['gmail.read'],'scopes':sorted(gm.BASE_SCOPES|{gm.SCOPE+'gmail.readonly'})}
        d=profile('destination');d['_google_migration']=c;d['authorized_user_json']['scopes']=c['scopes']
        gm.profile(d);gm.route(c,'gmail_profile',{},0)
    def test_workspace_actual_identity_and_returned_scopes_checked_before_read(self):
        for role in ('source','destination'):
            data=profile(role)
            for failure in ('account','verification','scope'):
                token={'access_token':'SYNTHETIC-ACCESS-TOKEN','expires_in':3600,
                       'token_type':'Bearer','scope':' '.join(data['_google_migration']['scopes'])}
                who={'email':data['_google_migration']['account'],'email_verified':True}
                if failure=='account':who['email']='other@example.test'
                if failure=='verification':who['email_verified']=False
                if failure=='scope':token['scope']='openid'
                with self.subTest(role=role,failure=failure), \
                     patch.object(gm,'exchange',side_effect=[(200,token),(200,who)]), \
                     patch.object(gm,'download') as remote:
                    self.denied(gm.GoogleMigration().execute,('fixture-project',role),data,
                                {'operation':'drive_about','params':{}},b'')
                    remote.assert_not_called()

    def test_workspace_invalid_route_or_body_cannot_start_authentication(self):
        cases=[
            ('source','drive_share',{'fileId':'file','sendNotificationEmail':True},
             {'type':'user','role':'reader','emailAddress':DESTINATION_ACCOUNT}),
            ('source','drive_share',{'fileId':'file'},
             {'type':'user','role':'writer','emailAddress':DESTINATION_ACCOUNT}),
            ('destination','drive_file_copy',{'fileId':'file'},
             {'name':'Copy','permissions':[{'role':'owner'}]}),
            ('destination','calendar_event_import',{'calendarId':'fixture@group.calendar.google.com'},
             {'iCalUID':'fixture','conferenceData':{'createRequest':{}}}),
        ]
        for role,operation,params,body in cases:
            proxy=gm.GoogleMigration()
            with self.subTest(role=role,operation=operation,body=body), \
                 patch.object(proxy,'token') as auth,patch.object(gm,'download') as remote:
                self.denied(proxy.execute,('fixture-project',role),profile(role),
                            {'operation':operation,'params':params},json.dumps(body).encode())
                auth.assert_not_called();remote.assert_not_called()

if __name__=='__main__':unittest.main()

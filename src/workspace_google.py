"""Fixed Drive, Calendar and People operations for the migration broker.

No delete, ownership transfer, invitations, arbitrary upload URLs or credential
handling. Source sharing is restricted to the profile's one destination user.
"""
import json
import re
import urllib.parse
from generic_api import ApiError

S = 'https://www.googleapis.com/auth/'
CAP_SCOPES = {
    'drive.read': {S+'drive'},
    'drive.share': {S+'drive'},
    'drive.copy': {S+'drive'},
    'calendar.read': {S+'calendar.readonly'},
    'calendar.import': {S+'calendar.app.created'},
    'contacts.read': {S+'contacts.readonly'},
    'contacts.other.read': {S+'contacts.other.readonly'},
    'contacts.create': {S+'contacts'},
}

# Each operation has an explicit capability, verb, path and parameter allowlist.
OPS = {
    'drive_about': ('drive.read','GET','drive','/about', ['fields']),
    'drive_files_list': ('drive.read','GET','drive','/files', ['q','pageSize','pageToken','fields','corpora','driveId','includeItemsFromAllDrives','supportsAllDrives','spaces']),
    'drive_file_get': ('drive.read','GET','drive','/files/{fileId}', ['fileId','fields','supportsAllDrives','resourceKey']),
    'drive_file_download': ('drive.read','GET','drive','/files/{fileId}', ['fileId','resourceKey']),
    'drive_file_export': ('drive.read','GET','drive','/files/{fileId}/export', ['fileId','mimeType','resourceKey']),
    'drive_permissions_list': ('drive.read','GET','drive','/files/{fileId}/permissions', ['fileId','fields','pageSize','pageToken','supportsAllDrives']),
    'drive_drives_list': ('drive.read','GET','drive','/drives', ['pageSize','pageToken','fields']),
    'drive_share': ('drive.share','POST','drive','/files/{fileId}/permissions', ['fileId']),
    'drive_folder_create': ('drive.copy','POST','drive','/files', ['fields']),
    'drive_file_copy': ('drive.copy','POST','drive','/files/{fileId}/copy', ['fileId','fields','supportsAllDrives']),
    'drive_shortcut_create': ('drive.copy','POST','drive','/files', ['fields']),
    'calendar_list': ('calendar.read','GET','calendar','/users/me/calendarList', ['maxResults','pageToken','showHidden']),
    'calendar_get': ('calendar.read','GET','calendar','/calendars/{calendarId}', ['calendarId']),
    'calendar_events_list': ('calendar.read','GET','calendar','/calendars/{calendarId}/events', ['calendarId','maxResults','pageToken','showDeleted','singleEvents','iCalUID','privateExtendedProperty','timeMin','timeMax']),
    'calendar_event_get': ('calendar.read','GET','calendar','/calendars/{calendarId}/events/{eventId}', ['calendarId','eventId']),
    'calendar_event_instances': ('calendar.read','GET','calendar','/calendars/{calendarId}/events/{eventId}/instances', ['calendarId','eventId','maxResults','pageToken','originalStart','showDeleted','timeMin','timeMax']),
    'calendar_private_event_patch': ('calendar.import','PATCH','calendar','/calendars/{calendarId}/events/{eventId}', ['calendarId','eventId','etag']),
    'calendar_create': ('calendar.import','POST','calendar','/calendars', []),
    'calendar_event_import': ('calendar.import','POST','calendar','/calendars/{calendarId}/events/import', ['calendarId']),
    'contacts_list': ('contacts.read','GET','people','/people/me/connections', ['personFields','pageSize','pageToken','sources']),
    'contact_get': ('contacts.read','GET','people','/people/{personId}', ['personId','personFields','sources']),
    'contact_groups_list': ('contacts.read','GET','people','/contactGroups', ['pageSize','pageToken','groupFields']),
    'contact_group_get': ('contacts.read','GET','people','/contactGroups/{groupId}', ['groupId','maxMembers','groupFields']),
    'other_contacts_list': ('contacts.other.read','GET','people','/otherContacts', ['pageSize','pageToken','readMask','sources']),
    'contact_create': ('contacts.create','POST','people','/people:createContact', ['personFields']),
    'contact_group_create': ('contacts.create','POST','people','/contactGroups', []),
    'contact_group_add': ('contacts.create','POST','people','/contactGroups/{groupId}/members:modify', ['groupId']),
}
HOSTS = {'drive':'https://www.googleapis.com/drive/v3',
         'calendar':'https://www.googleapis.com/calendar/v3',
         'people':'https://people.googleapis.com/v1'}
DRIVE_EXPORT_MIME_TYPES = frozenset({
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'image/svg+xml',
    'image/png',
    'text/plain',
})

def deny():
    raise ApiError('google_request_denied','This Workspace migration operation is not permitted.')

def segment(v, calendar=False):
    if not isinstance(v,str) or not v or len(v)>1024 or any(ord(c)<32 for c in v):deny()
    if not calendar and not re.fullmatch(r'[A-Za-z0-9_-]{1,256}',v):deny()
    if calendar and any(c in v for c in '/\\?#%'):deny()
    return urllib.parse.quote(v,safe='')

def required_scopes(caps):
    scopes=set().union(*(CAP_SCOPES[c] for c in caps if c in CAP_SCOPES))
    if 'contacts.create' in caps:scopes.discard(S+'contacts.readonly')
    return scopes

def route(config, operation, params, size):
    if operation not in OPS:deny()
    cap,method,service,path,allowed=OPS[operation]
    if cap not in config['capabilities']:deny()
    if not isinstance(params,dict) or set(params)-set(allowed):deny()
    if type(size) is not int or size<0 or size>4*1024*1024 or (method=='GET' and size) or (method!='GET' and not size):deny()
    q=dict(params)
    headers={}
    if 'resourceKey' in q:
        # Only the three read operations above allocate this parameter. Keep
        # it out of URLs; one validated file ID/key pair forms one fixed header.
        # No caller-controlled header names, multiple pairs or other hosts.
        resource_key=segment(q.pop('resourceKey'))
        file_id=segment(params.get('fileId'))
        headers['X-Goog-Drive-Resource-Keys']=file_id+'/'+resource_key
    if operation=='calendar_private_event_patch':
        # Primary calendars and unversioned updates are never allowed.
        if not str(q.get('calendarId','')).endswith('@group.calendar.google.com'):deny()
        etag=q.pop('etag',None)
        if not isinstance(etag,str) or not re.fullmatch(r'"[A-Za-z0-9_-]{1,256}"',etag):deny()
        headers['If-Match']=etag
    for key in re.findall(r'\{(\w+)\}',path):
        path=path.replace('{'+key+'}',segment(q.pop(key,None),calendar=key=='calendarId'))
    if operation=='drive_file_download':q={'alt':'media','supportsAllDrives':True}
    if operation=='drive_file_export':
        mime=q.get('mimeType')
        if not isinstance(mime,str) or mime not in DRIVE_EXPORT_MIME_TYPES:deny()
    # No list query can redirect the authenticated request to another server.
    for k,v in q.items():
        vs=v if isinstance(v,list) else [v]
        if len(vs)>100:deny()
        for x in vs:
            if type(x) not in (str,int,bool) or len(str(x))>4096 or any(ord(c)<32 for c in str(x)):deny()
        if k in ('maxResults','pageSize','maxMembers') and (type(v) is not int or not 1<=v<=2500):deny()
    if operation=='drive_share':q={'sendNotificationEmail':False,'supportsAllDrives':True,'fields':'id,type,role,emailAddress'}
    if operation=='calendar_event_import':
        # Do not create conferences or invite guests. This is a private import.
        q={'conferenceDataVersion':0,'supportsAttachments':True}
    if operation=='calendar_private_event_patch':
        q={'sendUpdates':'none','conferenceDataVersion':0,'supportsAttachments':True}
    # REST documentation uses sources[] to denote a repeated parameter; the
    # actual HTTP query key is sources, repeated via urlencode(doseq=True).
    q={k:([str(x).lower() if isinstance(x,bool) else x for x in v] if isinstance(v,list) else str(v).lower() if isinstance(v,bool) else v) for k,v in q.items()}
    url=HOSTS[service]+path
    if q:url+='?'+urllib.parse.urlencode(q,doseq=True)
    return method,url,headers,(10 if operation=='drive_file_export' else 32)*1024*1024

def validate_body(config, operation, body):
    if not body:return
    try:
        v=json.loads(body)
        if not isinstance(v,dict):deny()
        if operation=='drive_share':
            if v!={'type':'user','role':'reader','emailAddress':config.get('share_with')}:deny()
            if not config.get('share_with'):deny()
        elif operation in ('drive_folder_create','drive_file_copy','drive_shortcut_create'):
            allowed={'name','parents','appProperties'}
            if operation!='drive_file_copy':allowed|={'mimeType'}
            if operation=='drive_shortcut_create':allowed|={'shortcutDetails'}
            if set(v)-allowed or not isinstance(v.get('name'),str) or not v['name']:deny()
            parents=v.get('parents',[])
            if not isinstance(parents,list) or len(parents)>1:deny()
            for p in parents:segment(p)
            if operation=='drive_folder_create' and v.get('mimeType')!='application/vnd.google-apps.folder':deny()
            if operation=='drive_shortcut_create':
                if v.get('mimeType')!='application/vnd.google-apps.shortcut':deny()
                sd=v.get('shortcutDetails',{})
                if not isinstance(sd,dict) or set(sd)!={'targetId'}:deny()
                segment(sd['targetId'])
            props=v.get('appProperties',{})
            if not isinstance(props,dict) or len(props)>20 or any(not isinstance(k,str) or not isinstance(x,str) or len(k)+len(x)>124 for k,x in props.items()):deny()
        elif operation=='calendar_create':
            if set(v)-{'summary','description','timeZone'} or not isinstance(v.get('summary'),str) or not v['summary']:deny()
        elif operation=='calendar_event_import':
            fields={'id','iCalUID','summary','description','location','start','end','endTimeUnspecified','recurrence','recurringEventId','originalStartTime','status','transparency','visibility','sequence','organizer','attendees','extendedProperties','reminders','colorId','source','attachments','eventType'}
            if set(v)-fields or not v.get('iCalUID') or v.get('eventType','default')!='default':deny()
            if v.get('status') not in (None,'confirmed','tentative','cancelled'):deny()
            # Imported copies never send invitations; only existing attendees are
            # represented. Conference creation and attachments uploads are absent.
        elif operation=='calendar_private_event_patch':
            fields={'summary','description','location','start','end','endTimeUnspecified','status','transparency','visibility','attendees','extendedProperties','reminders','colorId','source','attachments'}
            if not v or set(v)-fields or v.get('status') not in (None,'confirmed','tentative'):deny()
            # No deletion/cancellation, organizer/recurrence changes, conference
            # creation or invitation controls. execute() verifies privateCopy and
            # migration markers with the same ETag before this PATCH can run.
        elif operation=='contact_create':
            fields={'addresses','biographies','birthdays','calendarUrls','clientData','emailAddresses','events','externalIds','genders','imClients','interests','locales','locations','memberships','miscKeywords','names','nicknames','occupations','organizations','phoneNumbers','relations','sipAddresses','skills','urls','userDefined'}
            if not v or set(v)-fields:deny()
        elif operation=='contact_group_create':
            if set(v)!={'contactGroup'} or not isinstance(v['contactGroup'],dict) or set(v['contactGroup'])!={'name'} or not isinstance(v['contactGroup']['name'],str) or not v['contactGroup']['name']:deny()
        elif operation=='contact_group_add':
            if set(v)!={'resourceNamesToAdd'} or not isinstance(v['resourceNamesToAdd'],list) or not 1<=len(v['resourceNamesToAdd'])<=1000:deny()
            for n in v['resourceNamesToAdd']:
                if not isinstance(n,str) or not n.startswith('people/'):deny()
                segment(n[7:])
        else:deny()
    except (ValueError,TypeError,KeyError):deny()

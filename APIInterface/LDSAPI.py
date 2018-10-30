'''
Created on 23/12/2013

@author: jramsay
'''

#https://koordinates.com/services/api/v1/sources/1/

import shlex
from abc import ABCMeta, abstractmethod
import json
import re
import os
import sys
import datetime as DT
import time
import base64

PYVER3 = sys.version_info > (3,)

#2 to 3 imports
if PYVER3:
	import http.cookiejar as cjar
	import urllib.request as ul2
	import urllib.parse as ul1
	from urllib.parse import urlparse as ULP
	from urllib.error import URLError as UE
	from urllib.error import HTTPError as HE
	from urllib.request import Request as REQ
else:
	import cookielib as cjar
	import urllib2 as ul2
	import urllib as ul1
	from urlparse import urlparse as ULP
	from urllib2 import URLError as UE
	from urllib2 import HTTPError as HE
	from urllib2 import Request as REQ



#from Main import CReader

#request = ul2.Request("http://api.foursquare.com/v1/user")
#base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
#request.add_header("Authorization", "Basic %s" % base64string)   
#result = ul2.urlopen(request)

REDIRECT = False
SLEEP_TIME = 5*60
SLEEP_RETRY = 5
MAX_RETRY_ATTEMPTS = 10

KEYINDEX = 0

class LDSAPI(object):

	__metaclass__ = ABCMeta

	sch = None
	sch_def = 'https'
	
	url = {'lds-l': 'data.linz.govt.nz',
		   'lds-t': 'data-test.linz.govt.nz',
		   'mfe-t': 'mfe.data-test.linz.govt.nz',
		   'apiary': 'private-cbd7-koordinates.apiary.io',
		   'koordinates': 'koordinates.com',
		   'ambury': 'ambury-ldsl.kx.gd'}
	url_def = 'lds-l'

	pxy = {'linz': 'webproxy1.ad.linz.govt.nz:3128',
		   'local': '127.0.0.1:3128'}
	pxy_def = 'local'
	
	ath = {'key':'.apikey3',#'api_llckey',
		   'basic':'.api_credentials'}
	ath_def = 'key'
	
	def __init__(self):#, creds, cfile):

		self.cookies = cjar.LWPCookieJar()
		#//

		self.setProxyRef(self.pxy_def)
		# cant set auth because we dont know yet what auth type to use, doesnt make sense to set up on default
		#self.setAuthentication(creds, self.ath[self.ath_def], self.ath_def)
		
		self.scheme = self.sch_def
		self.auth = None


	@abstractmethod
	def setParams(self):
		'''abstract host/path setting method'''
		
	def setCommonParams(self,scheme=None,host=None,format='json',sec=None,pth=None,url=None):
		'''Assigns path/host params or tries to extract them from a url'''
		self.format = format
		if url:
			p = ULP(url)
			self.scheme = p.scheme
			self.host = p.netloc
			self.path = p.path
			return
		if pth: self.path = self.path_ref[sec][pth]+'?format={0}'.format(self.format)
		if host: self.host = super(DataAPI, self).url[host]
		self.scheme = scheme or self.sch_def

	def setProxyRef(self, pref):
		#proxy = ul2.ProxyHandler({'http': self.pxy[pref]})
		#self.openerstrs_ntlm = ul2.build_opener(proxy)		
		self.openerstrs_ntlm = self.pxy[pref]	
		
	def setAuthentication(self, creds, cfile, auth):
		self.ath = {auth:self.ath[auth]}
		if auth == 'basic': 
			self._setBasicAuth(creds, cfile)
		elif auth == 'key':
			self._setKeyAuth(creds, cfile)
		else:
			raise Exception('Incorrect auth configuration supplied')
		
	def _setBasicAuth(self,creds,cfile):
		self.setCredentials(creds(cfile))
		self.setAuth("Basic {0}".format(self.b64a))
		
	def _setKeyAuth(self,creds,cfile):
		self.setKey(creds(cfile))
		self.setAuth("key {0}".format(self.key))
			
	def setCredentials(self, creds):
		if type(creds) is dict:
			self.usr, self.pwd, self.dom = [creds[i] for i in 'upd']
		else:
			self.usr, self.pwd, self.dom = creds
		self.b64a = self.encode(
			{'user': self.usr, 'pass': self.pwd, 'domain': self.dom} 
			if self.dom and self.dom != 'WGRP' else 
			{'user': self.usr, 'pass': self.pwd}
			)

	def setKey(self, creds):
		self.key = creds['k'] if type(creds) is dict else creds
		
	def setAuth(self,auth):
		self.auth = auth
		
	def setRequest(self,req):
		self.req = req
		
	def getRequest(self):
		return self.req	
		
	def setResponse(self,res):
		self.res = res
		self.data = res.read()
		self.info = res.info()
		self.head = LDSAPI.parseHeaders(self.info.headers) if hasattr(self.info,'headers') else None
		
	def getResponse(self):
		return {'info':self.info,'head':self.head,'data':self.data}
	
		
	@staticmethod
	def parseHeaders(head):
		# ['Server: nginx\r\n', 
		# 'Date: Wed, 14 May 2014 20:59:22 GMT\r\n', 
		# 'Content-Type: application/json\r\n', 
		# 'Transfer-Encoding: chunked\r\n', 
		# 'Connection: close\r\n', 
		# 'Vary: Accept-Encoding\r\n', 
		# 'Link: <https://data.linz.govt.nz/services/api/v1/layers/?sort=name&kind=raster&format=json>; 
		#	 rel="sort-name", 
		#	 <https://data.linz.govt.nz/services/api/v1/layers/?sort=-name&kind=raster&format=json>; 
		#	 rel="sort-name-desc", 
		#	 <https://data.linz.govt.nz/services/api/v1/layers/?kind=raster&page=1&format=json>; 
		#	 rel="page-previous", 
		#	 <https://data.linz.govt.nz/services/api/v1/layers/?kind=raster&page=3&format=json>; 
		#	 rel="page-next", 
		#	 <https://data.linz.govt.nz/services/api/v1/layers/?kind=raster&page=4&format=json>; 
		#	 rel="page-last"\r\n', 
		# 'Allow: GET, POST, HEAD, OPTIONS\r\n', 
		# 'Vary: Accept,Accept-Encoding\r\n', 
		# 'X-K-gentime: 0.716\r\n']
		h={}
		relist = {'server':'Server:\s(.*)\r\n',
				  'date':'Date:\s(.*)\r\n',
				  'content-type':'Content-Type:\s(.*)\r\n',
				  'transfer-encoding':'Transfer-Encoding:\s(.*)\r\n',
				  'connection':'Connection:\s(.*)\r\n',
				  'vary':'Vary:\s(.*)\r\n',
				  'link':'Link:\s(.*)\r\n',
				  'vary-acc':'Vary:\s(.*?)\r\n',
				  'x-k-gentime':'X-K-gentime:\s(.*?)\r\n'}

		for k in relist.keys():
			s = re.search(relist[k],'|'.join(head))
			if s: h[k] = s.group(1)

		# ---------------------
		lnlist = {'sort-name':'<(http.*?)>;\s+rel="sort-name"',
				  'sort-name-desc':'<(http.*?)>;\s+rel="sort-name-desc"',
				  'page-previous':'<(http.*?)>;\s+rel="page-previous"',
				  'page-next':'<(http.*?)>;\s+rel="page-next"',
				  'page-last':'<(http.*?)>;\s+rel="page-last"'}
		
		link = h['link'].split(',') if 'link' in h else []
		for ref in link:
			for rex in lnlist.keys():
				s = re.search(lnlist[rex],ref)
				if s:
					if 'page' in rex:
						p = re.search('page=(\d+)',s.group(1))
						h[rex] = {'u':s.group(1),'p':int(p.group(1)) if p else None}
					else:
						h[rex] = s.group(1)
					continue

		return h
		
	def opener(self,purl,puser=None,ppass=None,pscheme=('http','https')):
		if REDIRECT:				  
			h1,h2 = REDIRECT.BindableHTTPHandler,REDIRECT.BindableHTTPSHandler
		else:
			h1,h2 = ul2.HTTPHandler, ul2.HTTPSHandler
		
		handlers = [h1(), h2(), ul2.HTTPCookieProcessor(self.cookies)
				]
		if purl:
			handlers += [ul2.ProxyHandler({ps:purl for ps in pscheme}),]
			#handlers += [ul2.ProxyHandler({ps:purl}) for ps in pscheme]
		
		if puser and ppass:
			pm = ul2.HTTPPasswordMgrWithDefaultRealm()
			pm.add_password(None, purl, puser, ppass)
			handlers += [ul2.ProxyBasicAuthHandler(pm),]
		
		return ul2.build_opener(*handlers)

	def connect(self, plus='', head=None, data={}):		
		'''URL connection wrapper, wraps URL strings in request objects, applying selected openers'''
		
		#self.path='/services/api/v1/layers/{id}/versions/{version}/import/'
		self.setRequest(REQ('{0}://{1}{2}{3}'.format(self.scheme,self.host, self.path, plus)))
		
		# Add user header if provided 
		if head:
			self.getRequest().add_header(shlex.split(head)[0].strip("(),"),shlex.split(head)[1].strip("(),"))
			
		# Add user data if provided
		if data: #or true #for testing
			#NB. adding a data component in ul2 switches request from GET to POST
			data = urllib.urlencode(data)
			self.getRequest().add_data(data)
			
		return self.conn(self.getRequest())

	def conn(self,request):
		'''URL connection wrappercatching common exceptions and retrying where necessary
		param: request can be either a url string or a request object
		'''
		if isinstance(request,str) or isinstance(request,basestring):
			self.setRequest(REQ(request))
			
		if self.auth:
			self.getRequest().add_header("Authorization", self.auth)
			
		ul2.install_opener(self.opener(purl=self.openerstrs_ntlm))
		
		retry = MAX_RETRY_ATTEMPTS
		while retry:
			try:
				handle = ul2.urlopen(self.getRequest())#,data)
				if handle: return handle
				#self.setResponse(handle)
				#break
			except HE as he:
				if re.search('429',str(he)):
					print ('RateLimit Error {0}. Sleeping for {1} seconds awaiting 429 expiry. Attempt {2}'.format(he,SLEEP_TIME,MAX_RETRY_ATTEMPTS-retry))
					time.sleep(SLEEP_TIME)
					retry -= 1
					continue
				elif re.search('401|500',str(he)):
					print ('HTTP Error {0} Returns {1}. Attempt {2}'.format(self.getRequest().get_full_url(),he,MAX_RETRY_ATTEMPTS-retry))
					retry -= 1
					continue
				else:
					print ('Error with request {0} returns {1}'.format(self.getRequest().get_full_url(),he))
			except UE as ue: 
				print('URL error on connect', ue)
				print(ul2.request.getproxies())
				raise ue
			except ValueError as ve: 
				print('Value error on connect', ve)
				raise ve
			except KeyError as ee:
				#redundant now since link keyerror caught in parseHeaders
				if not re.search('link',str(ee)): raise
				retry = 0
			except Exception as xe:
				print('Other error on connect', xe)
		else:
			raise ee
		#except Exception as e:
		#	print e
		
	def _testalt(self,ref='basic'):
		p = os.path.join(os.path.dirname(__file__),cxf or LDSAPI.ath[ref])
		self.setAuthentication(Authentication.creds,p, ref)
		
	def encode(self,auth):
		return base64.encodestring('{0}:{1}'.format(auth['user'], auth['pass'])).replace('\n', '')

	def fetchPages(self,psub=''):
		
		upd = []
		page = 0
		pagel = None
		morepages = True
		while morepages:
			page = page + 1
			pstr = psub+'&page={0}'.format(page)
			try:
				self.connect(plus=pstr)
				#api.dispReq(api.req)
				#api.dispRes(api.res)
			except HE:
				morepages = False
				raise
				#continue
			#the logic here is weird/redundant, if no last page then its the last page otherwise save the last page and finish when page is last
			if 'page-last' in self.head: 
				pagel = self.head['page-last']['p']
			else:
				morepages = False
				
			if page == pagel:
				morepages = False
			
			jdata = json.loads(self.data)
			upd += [jdata,] if isinstance(jdata,dict) else jdata
					
		return upd
	
	def dispReq(self,req):
		print ('Request\n-------\n')
		print (req.get_full_url(),'auth',req.get_header('Authorization'))
		
	def dispRes(self,res):
		print ('Response\n--------\n')
		print (res.info())
	
	def dispJSON(self,res):
		for l in json.loads(res.read()):
			print ('{0} - {1}\n'.format(l[0],l[1]))
		
	def _populate(self,data):
		return json.dumps({"name": data[0],"type": data[1],"description": data[2], 
					  "categories": data[3], "user": data[4], "options":{"username": data[5],"password": data[6]},
					  "url_remote": data[7],"scan_schedule": data[8]})
			  
# GET
# /services/api/v1/data/
# Read-only, filterable list views.

# GET
# /services/api/v1/layers/
# Filterable views of layers (at layers/) and tables (at tables/) respectively.

# POST
# /services/api/v1/layers/
# Creates a new layer. All fields except name and data.datasources are optional.

# GET
# /services/api/v1/layers/drafts/
# A filterable list views of layers (layers/drafts/) and and tables (tables/drafts/) respectively, similar to /layers/ and /tables/. This view shows the draft version of each layer or table

#--------------------------------DataAccess
# GET
# /services/api/v1/layers/{id}/
# Displays details of a layer layers/{id}/ or a table tables/{id}/.

# POST
# /services/api/v1/layers/{id}/versions/
# Creates a new draft version, accepting the same content as POST layers/.

# GET
# /services/api/v1/layers/{id}/versions/draft/
# Get a link to the draft version for a layer or table.

# GET
# /services/api/v1/layers/{id}/versions/published/
# Get a link to the current published version for a layer or table.

# GET
# /services/api/v1/layers/{id}/versions/{version}/
# Get the details for a specific layer or table version.

# PUT
# /services/api/v1/layers/{id}/versions/{version}/
# Edits this draft layerversion. If it's already published, a 405 response will be returned.

# POST
# /services/api/v1/layers/{id}/versions/{version}/import/
# Starts importing this draft layerversion (cancelling any running import), even if the data object hasn't changed from the previous version.

# POST
# /services/api/v1/layers/{id}/versions/import/
# A shortcut to create a new version and start importing it.

# POST
# /services/api/v1/layers/{id}/versions/{version}/publish/
# Creates a publish task just for this version, which publishes as soon as any import is complete.

# DELETE
# /services/api/v1/layers/{id}/versions/{version}/


class DataAPI(LDSAPI):
	path_ref = {'list':
						{'dgt_data'		 :'/services/api/v1/data/',
						 'dgt_layers'	   :'/services/api/v1/layers/',
						 'dgt_tables'	   :'/services/api/v1/tables/',
						 'dpt_layers'	   :'/services/api/v1/layers/',
						 'dpt_tables'	   :'/services/api/v1/tables/',
						 'dgt_draftlayers'  :'/services/api/v1/layers/drafts/',
						 'dgt_drafttables'  :'/services/api/v1/tables/drafts/'},
				  'detail':
						{'dgt_layers'	   :'/services/api/v1/layers/{id}/',
						 'dgt_tables'	   :'/services/api/v1/tables/{id}/',
						 'ddl_delete'	   :'/services/api/v1/layers/{id}/'},
				  'access':
						{'dgt_permissions'  :'/services/api/v1/layers/{id}/permissions/'},
				  'version':
						{'dgt_version'	  :'/services/api/v1/layers/{id}/versions/',
						 'dpt_version'	  :'/services/api/v1/layers/{id}/versions/',
						 'dgt_draftversion' :'/services/api/v1/layers/{id}/versions/draft/',
						 'dgt_publicversion':'/services/api/v1/layers/{id}/versions/published/',
						 'dgt_versioninfo'  :'/services/api/v1/layers/{id}/versions/{version}/',
						 'dpu_draftversion' :'/services/api/v1/layers/{id}/versions/{version}/',
						 'dpt_importversion':'/services/api/v1/layers/{id}/versions/{version}/import/',
						 'dpt_publish'	  :'/services/api/v1/layers/{id}/versions/{version}/publish/',
						 'ddl_delete'	   :'/services/api/v1/layers/{id}/versions/{version}/'},
				  'publish':
						{'dpt_publish'	  :'/services/api/v1/publish/',
						 'dgt_publish'	  :'/services/api/v1/publish/{id}/',
						 'ddl_delete'	   :'/services/api/v1/publish/{id}/'},
				  'permit':{},
				  'metadata':
						{'dgt_metadata'	 :'/services/api/v1/layers/{id}/metadata/',
						 'dgt_metaconv'	 :'/services/api/v1/layers/{id}/metadata/{type}/',
						 'dgt_metaorig'	 :'/services/api/v1/layers/{id}/versions/{version}/metadata/',
						 'dgt_metaconvver'  :'/services/api/v1/layers/{id}/versions/{version}/metadata/{type}/'},
				  'unpublished':
						{'dgt_users':'/services/api/v2/users/'}#this of course doesn't work
				  }
	
	def __init__(self):
		super(DataAPI,self).__init__()
		
	def setParams(self, sec='list', pth='dgt_data', host=LDSAPI.url_def, format='json', id=None, version=None, type=None):
		super(DataAPI,self).setCommonParams(host=h,format=format,sec=sec,pth=pth)
		
		if id and re.search('{id}',self.path): self.path = self.path.replace('{id}',str(id))
		if version and re.search('{version}',self.path): self.path = self.path.replace('{version}',str(version))
		if type and re.search('{type}',self.path): self.path = self.path.replace('{type}',str(type))
		
		#self.host = super(DataAPI, self).url[host]
		
class SourceAPI(LDSAPI):
	path_ref = {'list':
					{'sgt_sources':'/services/api/v1/sources/',
					 'spt_sources':'/services/api/v1/sources/'},
				'detail':
					{'sgt_sources':'/services/api/v1/sources/{id}/',
					 'spt_sources':'/services/api/v1/sources/{id}/'},
				'metadata':
					{'sgt_metadata':'/services/api/v1/sources/{id}/metadata/',
					 'spt_metadata':'/services/api/v1/sources/{id}/metadata/',
					 'spt_metatype':'/services/api/v1/sources/{id}/metadata/{type}/'},
				'scans':
					{'sgt_scans':'/services/api/v1/sources/{source-id}/',
					 'spt_scans':'/services/api/v1/sources/{source-id}/',
					 'sgt_scanid':'/services/api/v1/sources/{source-id}/scans/{scan-id}/',
					 'sdt_scandelete':'/services/api/v1/sources/{source-id}/scans/{scan-id}/',
					 'sgt_scanlog':'/services/api/v1/sources/{source-id}/scans/{scan-id}/log/'},
				'datasource':
					{'sgt_dslist':'/services/api/v1/sources/{source-id}/datasources/',
					 'sgt_dsinfo':'/services/api/v1/sources/{source-id}/datasources/{datasource-id}/',
					 'sgt_dsmeta':'/services/api/v1/sources/{source-id}/datasources/{datasource-id}/metadata/',
					 },
				'groups':
					{'sgt_groups':'/services/api/v1/groups/',
					 'sgt_groupid':'/services/api/v1/groups/{id}/'}
				}
	
	def __init__(self):
		super(SourceAPI,self).__init__()
		
	def setParams(self,sec='list',pth='sgt_sources',host='lds-l',format='json',id=None,type=None,source_id=None,scan_id=None,datasource_id=None):
		super(DataAPI,self).setCommonParams(host=h,format=format,sec=sec,pth=pth)

		#insert optional args if available
		if id and re.search('{id}',self.path): self.path = self.path.replace('{id}',str(id))
		if type and re.search('{type}',self.path): self.path = self.path.replace('{type}',str(type))
		if source_id and re.search('{source-id}',self.path): self.path = self.path.replace('{source-id}',str(source_id))
		if scan_id and re.search('{scan-id}',self.path): self.path = self.path.replace('{scan-id}',str(scan_id))
		if datasource_id and re.search('{datasource-id}',self.path): self.path = self.path.replace('{datasource-id}',str(datasource_id))
		
		#self.host = super(SourceAPI,self).url[host]
		
# GET
# /services/api/v1/layers/{id}/redactions/
# Displays a detailed list of redactions for the layer.

# POST
# /services/api/v1/layers{id}/redactions/
# Creates a new redaction for layer {id}.
# 
# Note that start_version <= affected versions <= end_version
#	 primary_key: The primary key(s) for the item being redacted. This should identify a single feature.
#	 start_version: The URL of the first layer version to perform the redaction on.
#	 end_version: (Optional) The URL of the last layer version to perform the redaction on.
#	 new_values: The new values for the row. This can be any subset of fields and only specified fields will be redacted.
#	 message: A message to be stored with the redaction.

# GET
# /services/api/v1/layers/{id}/redactions/{redaction}/
# Gets information about a specific redaction.

class RedactionAPI(LDSAPI):
	path_ref = {'list':
					{'rgt_disp'  :'/services/api/v1/layers/{id}/redactions/',
					 'rpt_disp'  :'/services/api/v1/layers/{id}/redactions/'},
				'redact':
					{'rgt_info':'/services/api/v1/layers/{id}/redactions/{redaction}/'}
				}
	
	def __init__(self):
		super(RedactionAPI,self).__init__()
		
	def setParams(self,sec='list',pth='rgt_disp',h='lds-l',format='json',id=None,redaction=None):
		super(DataAPI,self).setCommonParams(host=h,format=format,sec=sec,pth=pth)
		
		#insert optional args if available
		if id and re.search('{id}',self.path): self.path = self.path.replace('{id}',str(id))
		if redaction and re.search('{redaction}',self.path): self.path = self.path.replace('{redaction}',str(redaction))
		
		#self.host = super(RedactionAPI,self).url[h]
		
class APIAccess(object):
	defs = (LDSAPI.url_def, LDSAPI.pxy_def, LDSAPI.ath_def)
	
	def __init__(self, apit, creds, cfile, refs):
		self.api = apit() # Set a data, src or redact api
		self.uref,self.pref,self.aref = refs
		self.api.setProxyRef(self.pref)
		self.api.setAuthentication(creds, cfile, self.aref)


	def readAllPages(self):
		'''Calls API custom page reader'''
		self.api.setParams(sec='list',pth=self.path,host=self.uref)
		return self.api.fetchPages()
		
	def readAllIDs(self):
		'''Extracts and returns IDs from reading all-pages'''
		return [p['id'] for p in self.readAllPages() if 'id' in p]	
	
	
class SourceAccess(APIAccess):
	'''Convenience class for accessing sourceapi data'''
	def __init__(self,creds,ap_creds, uref=LDSAPI.url_def, pref=LDSAPI.pxy_def, aref=LDSAPI.ath_def):
		super(SourceAccess,self).__init__(SourceAPI,creds,ap_creds, (uref, pref, aref))
		self.path = 'sgt_sources'

	#TODO. Implement these functions
	def writeDetailFields(self):
		pass
	def writePermissionFields(self):
		pass
	def writeSelectedFields(self):
		pass
	def writePrimaryKeyFields(self):
		pass
	
class RedactionAccess(APIAccess):
	'''Convenience class for redacting api data'''
	def __init__(self,creds,ap_creds, uref=LDSAPI.url_def, pref=LDSAPI.pxy_def, aref=LDSAPI.ath_def):
		super(RedactionAccess,self).__init__(RedactionAPI,creds,ap_creds, (uref, pref, aref))
		self.path = 'sgt_sources'

	#TODO. Implement these functions
	def redactDetailFields(self):
		pass
	def redactPermissionFields(self):
		pass
	def redactSelectedFields(self):
		pass
	def redactPrimaryKeyFields(self):
		pass
	
class StaticFetch():
	
	UREF = LDSAPI.url_def
	PREF = LDSAPI.pxy_def
	AREF = LDSAPI.ath_def
		
	@classmethod
	def get(cls,uref=None,pref=None,korb=None,cxf=None):
		uref = uref or cls.UREF
		pref = pref or cls.PREF
		if korb: aref = korb.lower()
		else: aref = cls.AREF
		p = os.path.join(os.path.dirname(__file__),cxf or LDSAPI.ath[aref])
		method = (Authentication.creds,p) if aref=='basic' else (Authentication.apikey,p)
		
		da = DataAccess(*method,uref=uref,pref=pref,aref=aref)
		return da.api.conn(uref)
		#return res or da.api.getResponse()['data']
		
class DataAccess(APIAccess):
	'''Convenience class for accessing commonly needed data-api data'''
	
	def __init__(self, creds, cfile, uref=LDSAPI.url_def, pref=LDSAPI.pxy_def, aref=LDSAPI.ath_def):
		super(DataAccess, self).__init__(DataAPI, creds, cfile, (uref, pref, aref))
		self.path = 'dgt_layers'
		self.dpath = 'dgt_layers'
		self.ppath = 'dgt_permissions'
		
	def _set(self,l,nl=None):
		'''fetch if value present in path and returns utf encoded'''
		if nl: 
			for ni in nl:
				if l and (ni in l or (isinstance(ni,int) and isinstance(l,(list,tuple)))):
					l = l[ni]
				else:
					l = None
		if isinstance(l, unicode):
			return l.encode('utf8')
		else:
			return l 
		#if n2: return l[n1][n2].encode('utf8') if n1 in l and n2 in l[n1] else None
		#else: return l[n1].encode('utf8') if n1 in l else None
	
	def readDetailFields(self,i):
		'''All field from detail pages'''
		self.api.setParams(sec='detail',pth=self.dpath,host='lds-l',id=i)
		return self.api.fetchPages()[0]
	
	def readPermissionFields(self,i):
		'''All field from permission pages'''
		self.api.setParams(sec='access',pth=self.ppath,host='lds-l',id=i)
		pge = [p for p in self.api.fetchPages() if p['id']=='group.everyone']
		return pge[0] if pge else None
		
	def readSelectedFields(self,pagereq=('data','permission')):
		'''Not all fields, just the ones we're interested in'''
		detail = {}
		herror = {}
		
		for i in self.readAllIDs():
		#print 'WARNING. READING LDS-API-ID SUBSET'
		#for i in [1572,1993,2052,1293,2100]:#[1993,1996,1624,2268,626,407]:
			detail[str(i)] = {}
			if 'data' in pagereq:
				try:
					d = self.readDetailFields(i)
				except HE as he:
					herror[str(i)] = he
					continue
				try:
					dx = {'name':('name',),'type':('type',),'group':('group','id'),'kind':('kind',),'cat':('categories',0,'slug'),'crs':('data','crs'),\
						  'lic-ttl':('license','title'),'lic-typ':('license','type'),'lic-ver':('license','version'),\
						  'data-pky':('data','primary_key_fields'),'data-geo':('data','geometry_field'),'data-fld':('data','fields'),\
						  'date-pub':('published_at',),'date-fst':('first_published_at',),'date-crt':('created_at',),'date-col':('collected_at',)
						  }
					dd = {k:self._set(d,dx[k]) for k in dx}
					#special postprocess
					dd['data-pky'] = self._set(','.join(dd['data-pky']))  
					dd['data-fld'] = self._set(','.join([f['name'] for f in dd['data-fld']]))   
					detail[str(i)].update(dd)

				except IndexError as ie:
					#not raising this as an error since it only occurs on 'test' layers
					print ('{0} error getting {1},{2}'.format(ie,d['id'],d['name']))
				except TypeError as te:
					print ('{0} error on layer {1}/{2}'.format(te,d['id'],d['name']))
					continue
				except Exception as e:
					print ('{0} error on layer {1}/{2}'.format(e,d['id'],d['name']))
					raise
			
			if 'permission' in pagereq:
				try:
					#returns the permissions for group.everyone only
					p = self.readPermissionFields(i)
				except HE as he:
					herror[str(i)] = he
					continue
				
				try:
					px = {'prm-grp':('id',),'prm-typ':('permission',),'prm-name':('group','name')}
					pp = {k:self._set(p,px[k]) for k in px} if p else {p:None for p in px}
					detail[str(i)].update(pp)

				except IndexError as ie:
					#not raising this as an error since it only occurs on 'test' layers
					print ('{0} error getting {1},{2}'.format(ie,i,p['name']))
				except TypeError as te:
					print ('{0} error on layer {1}/{2}'.format(te,i,p['name']))
					continue
				except Exception as e:
					print ('{0} error on layer {1}/{2}'.format(e,d['id'],d['name']))
					raise				

		return detail,herror
	
	def readPrimaryKeyFields(self):
		'''Read PrimaryKey field from detail pages'''
		d,_ = self.readSelectedFields(pagereq=('data',))
		res = [i for i in d]
		print (res)

'''Copied from LDSChecker for availability'''
		
class Authentication(object):
	'''Static methods to read keys/user/pass from files'''
	
	@staticmethod
	def userpass(upfile):
		return (Authentication.searchfile(upfile,'username'),Authentication.searchfile(upfile,'password'))
		
	@staticmethod
	def apikey(keyfile,kk='key',keyindex=None):
		'''Returns current key from a keyfile advancing KEYINDEX on subsequent calls (if ki not provided)'''
		global KEYINDEX
		key = Authentication.searchfile(keyfile,'{0}{1}'.format(kk,keyindex or KEYINDEX))
		if not key and not keyindex:
			KEYINDEX = 0
			key = Authentication.searchfile(keyfile,'{0}{1}'.format(kk,KEYINDEX))
		elif not keyindex:
			KEYINDEX += 1
		return key
	
	@staticmethod
	def creds(cfile):
		'''Read CIFS credentials file'''
		return (Authentication.searchfile(cfile,'username'),\
				Authentication.searchfile(cfile,'password'),\
				Authentication.searchfile(cfile, 'domain'))
	
	@staticmethod
	def searchfile(spf,skey,default=None):
		#value = default
		#look in current then app then home
		sp,sf = os.path.split(spf)
		spath = (sp,'',os.path.expanduser('~'),os.path.dirname(__file__))
		first = [os.path.join(p,sf) for p in spath if os.path.lexists(os.path.join(p,sf))][0]
		with open(first,'r') as h:
			for line in h.readlines():
				k = re.search('^{key}=(.*)$'.format(key=skey),line)
				if k: return k.group(1)
		return default
	
	@staticmethod
	def getHeader(korb,kfile):
		'''Convenience method for auth header'''
		if korb.lower() == 'basic':
			b64s = base64.encodestring('{0}:{1}'.format(*Authentication.userpass(kfile))).replace('\n', '')
			return ('Authorization', 'Basic {0}'.format(b64s))
		elif korb.lower() == 'key':
			key = Authentication.apikey(kfile)
			return ('Authorization', 'key {0}'.format(key))
		return None # Throw something


class APIFunctionTest(object):
	'''Class will not run as-is but illustrates by example api ue and the paging mechanism'''
	credsfile = os.path.abspath(os.path.join(os.path.dirname(__file__),'..','.test_credentials'))
	
	def _getCreds(self,cfile):
		return 'user','pass','domain'
	
	def _getPages(self):
		api = DataAPI(creds,self.credsfile)
		api.setParams(sec='list',pth='dgt_layers',host='lds-l')
		
		return api.fetchPages()
	
	def _getUsers(self):
		api = DataAPI(creds,self.credsfile)
		api.setParams(sec='unpublished',pth='dgt_users',host='lds-l')
		
		return api.fetchPages()
	
	def _getLastPubLayers(self,lk):
		'''Example function fetching raster layer id's with their last published date'''
		api = DataAPI(creds,self.credsfile)
		api.setParams(sec='list',pth='dgt_layers',host='lds-l')
		
		pages = api.fetchPages('&kind={0}'.format(lk))

		return [(p['id'],DT.datetime(*map(int, re.split('[^\d]', p['published_at'])[:-1]))) for p in pages if 'id' in p and 'published_at' in p]
	
	def _testSA(self):
		sa = SourceAccess(creds,self.credsfile)
		#print sa.readAllIDs()
		res = sa.readAllPages()
		lsaids = [(r['id'],r['last_scanned_at']) for r in res if r['last_scanned_at']]
		for lid,dt in lsaids:
			print ('layer {} last scanned at {}'.format(lid,dt))	
			
	def _testDA(self):
		da = DataAccess(creds,self.credsfile)
		#print sa.readAllIDs()
		res = da.readPrimaryKeyFields()
		
	def _testSF(self):
		#,plus='',head=None,data={}
		res1 = StaticFetch.get(uref='https://data.linz.govt.nz/layer/51424',korb='KEY',cxf='.apikey3')
		print(res1)
		res2 = StaticFetch.get(uref='https://data.linz.govt.nz/layer/51414')
		print(res2)
		
def creds(cfile):
	'''Read CIFS credentials file'''
	return {
		'u':searchfile(cfile,'username'),
		'p':searchfile(cfile,'password'),
		'd':searchfile(cfile,'domain','WGRP'),
		'k':searchfile(cfile,'key')
		}

def searchfile(sfile,skey,default=None):
	value = default
	with open(sfile,'r') as h:
		for line in h.readlines():
			k = re.search('^{key}=(.*)$'.format(key=skey),line)
			if k: value=k.group(1)
	return value
		
	
def main():
	global REDIRECT
	if REDIRECT:
		import BindingIPHandler as REDIRECT
		bw = REDIRECT.BindableWrapper()
		bw.getLocalIP(True)

	t = APIFunctionTest()
	#print t._getLastPubLayers(lk='raster')
	#t._testSA()
	#t._testDA()
	t._testSF()

	
	#print t._getUsers()
	
if __name__ == '__main__':
	main()	   

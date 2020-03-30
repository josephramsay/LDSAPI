'''
Created on 23/12/2013

@author: jramsay
'''

#https://koordinates.com/services/api/v1/sources/1/

import shlex
from abc import ABC, abstractmethod #, ABCMeta
import json
import re
import os
import datetime as DT
import time
import base64


#from http.client import HTTPMessage
from six.moves.http_client import HTTPMessage
from six.moves import http_cookiejar as cjar
from six.moves.urllib import request
#from six.moves.urllib import parse as ul1
from six.moves.urllib.parse import urlparse, urlencode
from six.moves.urllib.error import URLError
from six.moves.urllib.error import HTTPError
from six.moves.urllib.request import Request
from six import string_types
	
try:
	from LDSUtilityScripts.LinzUtil import LogManager, Authentication, LDS
except ImportError:
	from LinzUtil import LogManager, Authentication, LDS
	
try:
	from http.client import RemoteDisconnected as HttpResponseError
except ImportError:
	from http.client import BadStatusLine as HttpResponseError


#from Main import CReader

#request = ul2.Request("http://api.foursquare.com/v1/user")
#base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
#request.add_header("Authorization", "Basic %s" % base64string)   
#result = ul2.urlopen(request)

REDIRECT = False
SLEEP_TIME = 5*60
SLEEP_RETRY_INCR = 5
MAX_RETRY_ATTEMPTS = 10
INIT_MAX_RETRY_ATTEMPTS = 100

KEYINDEX = 0
LM = LogManager()
LM.register()

class LDSAPI(ABC):
#class LDSAPI(object):
#	__metaclass__ = ABCMeta

	__sec = 'LDSAPI Wrapper'
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
		   'local': '127.0.0.1:3128',
		   'noproxy':':'}
	pxy_def = 'noproxy'
	
	ath = {'key':'.apikey3',#'api_llckey',
		   'basic':'.credentials'}
	ath_def = 'key'
	
	def __init__(self):#, creds, cfile):

		self.cookies = cjar.LWPCookieJar()
		#//

		self.setProxyRef(self.pxy_def)
		# cant set auth because we dont know yet what auth type to use, doesnt make sense to set up on default
		# self.setAuthentication(creds, self.ath[self.ath_def], self.ath_def)
		
		self.scheme = self.sch_def
		self.auth = None
		self.head = {}


	@abstractmethod
	def setParams(self):
		'''abstract host/path setting method'''
		pass
		
	def setCommonParams(self,scheme=None,host=None,fmt='json',sec=None,pth=None,url=None):
		'''Assigns path/host params or tries to extract them from a url'''
		self.fmt = fmt
		if url:
			p = urlparse(url)
			self.scheme = p.scheme
			self.host = p.netloc
			self.path = p.path
			return
		if pth: self.path = self.path_ref[sec][pth]+'?format={0}'.format(self.fmt)
		if host: self.host = super(DataAPI, self).url[host]
		self.scheme = scheme or self.sch_def

	def setProxyRef(self, pref):
		#proxy = ul2.ProxyHandler({'http': self.pxy[pref]})
		#self.openerstrs_ntlm = ul2.build_opener(proxy)		
		self.pref = pref
		self.openerstrs_ntlm = self.pxy[pref]	
		
	def setAuthentication(self, creds, cfile, auth):
		self.ath = {auth:self.ath[auth]}
		if auth == 'basic': 
			self._setBasicAuth(creds, cfile)
		elif auth == 'key':
			self._setKeyAuth(creds, cfile)
		else:
			LM.err('Auth error. Need key/basic specifier',LM._LogExtra('LDSAPI','sA'))
			raise Exception('Incorrect auth configuration supplied')
		
	def _setBasicAuth(self,creds,cfile):
		self.setCredentials(creds(cfile))
		self._setRequestAuth("Basic {0}".format(self.b64a))
		
	def _setKeyAuth(self,creds,cfile):
		self._setRequestKey(creds(cfile))
		self._setRequestAuth("key {0}".format(self.key))
			
	def setCredentials(self, creds):
		if type(creds) is dict:
			self.usr, self.pwd, self.dom = [creds[i] for i in 'upd']
		else:
			self.usr = 'pp'
			#self.usr, self.pwd, self.dom = (*creds,None,None)[:3] #only since py3.5
			self.usr, self.pwd, self.dom = (creds+(None,None))[:3]
		self.b64a = LDSAPI.encode_auth(
			{'user': self.usr, 'pass': self.pwd, 'domain': self.dom} 
			if self.dom and self.dom != 'WGRP' else 
			{'user': self.usr, 'pass': self.pwd}
			)

		#---------------------------------------------------------------------------

	def _setRequestKey(self, creds):
		self.key = creds['k'] if type(creds) is dict else creds
		
	def _setRequestAuth(self,auth):
		self.auth = auth
		
	def setRequest(self,req):
		if isinstance(req,string_types):
			self.req_str = req
			self.req = Request(req)
		else:
			self.req_str = req.full_url
			self.req = req
			
	def _setRequestData(self,data):
		self.data = data
		
	def _setRequestInfo(self,info):
		self.info = info
		
	def _setRequestHead(self,name,val):
		self.head[name] = val
		
	def addRequestHeader(self,name,head):
		self.req.add_header(name,head)
		
	def addRequestData(self,data=None):
		self.req.add_data(data if data else self.data)
		
	def getRequest(self):
		return self.req

	def getRequestStr(self,mask = True):
		return LDS.kmask(self.req_str) if mask else self.req_str
	
	#---------------------------------------------------------------------------
	
	def setResponse(self,res):
		self.res = res
		self._setResponseData(res.read())
		self._setResponseInfo(res.info())
		self._setResponseURL(res.geturl())
		self._setResponseHead(LDSAPI.parseHeaders(self.info._headers) if hasattr(self.info,'_headers') else None)
		
	def _setResponseData(self,respdata):
		self.respdata = respdata
		
	def _setResponseHead(self,head):
		self.head = head
		
	def _setResponseInfo(self,info):
		self.info = info
		
	def _setResponseURL(self,url):
		self.url = url
		
	def getResponse(self):
		return {'info':self.respinfo,'head':self.resphead,'data':self.respdata}
	
	#---------------------------------------------------------------------------
	
	def setExteralLogManager(self,lm):
		global LM
		LM = lm
	
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
				  'x-k-gentime':'X-K-gentime:\s(.*?)\r\n',
				  'oauth-scopes':'OAuth-Scopes:\s(.*?)\r\n'}

		if isinstance(head,HTTPMessage):
			for k in relist.keys():
				s = [i[1] for i in head._headers if i[0].lower()==k]
				if s: h[k] = s[0]
		elif isinstance(head,string_types):
			for k in relist.keys():
				s = re.search(relist[k],'|'.join(head))
				if s: h[k] = s.group(1)
		elif isinstance(head,list):
			for k in relist.keys():
				s = [i[1] for i in head if i[0].lower()==k]
				if s: h[k] = s[0]
				
		# ---------------------
		#Pull apart link string, if its available
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
			h1,h2 = request.HTTPHandler, request.HTTPSHandler
		
		handlers = [h1(), h2(), request.HTTPCookieProcessor(self.cookies)]
		
		if self.pref != 'noproxy' and purl and len(purl)>1:
			#if not noproxy and a proxy url is provided (and its not the placeholder url ie noproxy=':') add a handler
			handlers += [request.ProxyHandler({ps:purl for ps in pscheme}),]
			#handlers += [request.ProxyHandler({ps:purl}) for ps in pscheme]
		
			if puser and ppass:
				#if proxy user/pass provided and a proxy auth handler
				pm = request.HTTPPasswordMgrWithDefaultRealm()
				pm.add_password(None, purl, puser, ppass)
				handlers += [request.ProxyBasicAuthHandler(pm),]
		
		return request.build_opener(*handlers)

	def connect(self, plus='', head=None, data={}, auth=None):		
		'''URL connection wrapper, wraps URL strings in request objects, applying selected openers'''
		
		#self.path='/services/api/v1/layers/{id}/versions/{version}/import/'
		self.setRequest('{0}://{1}{2}{3}'.format(self.scheme,self.host, self.path, plus))
		
		# Add user header if provided 
		if head:
			self._setRequestHead(head)
			self.addRequestHeader(shlex.split(head)[0].strip("(),"),shlex.split(head)[1].strip("(),"))
		
		if auth:
			self._setRequestAuth(auth)
			self.addRequestHeader("Authorization", auth)
			
		# Add user data if provided
		if data: #or true #for testing
			#NB. adding a data component in request switches request from GET to POST
			data = urlencode(data)
			self._setRequestData(data)
			self.addRequestData(data)
			
		return self.conn(self.getRequest())

	def conn(self,req):
		'''URL connection wrappercatching common exceptions and retrying where necessary
		param: connreq can be either a url string or a request object
		'''
		sr = self.__sec,'Connection Manager'
		self.setRequest(req)
		req_str = self.getRequestStr()

		#if self.auth is set it should have been added to the request header... might be legacy where that hasn't happened
		if self.auth:
			self.addRequestHeader("Authorization", self.auth)
			
		request.install_opener(self.opener(purl=self.openerstrs_ntlm))
		
		retry = INIT_MAX_RETRY_ATTEMPTS
		while retry>0:
			retry -= 1
			try:
				handle = request.urlopen(self.getRequest())#,data)
				if handle: 
					if handle.geturl()!=req_str:
						msg = 'Redirect Warning'
						#cannot easily mask redirected url so logging original
						LM.info(msg,LM._LogExtra(*sr,exc=None,url=req_str,rty=0))
					return handle
				#self.setResponse(handle)
				#break
			except HTTPError as he:
				last_exc = he
				if re.search('429',str(he)):
					msg = 'RateLimit Error {0}. Sleep awaiting 429 expiry. Attempt {1}'.format(he,MAX_RETRY_ATTEMPTS-retry)
					LM.error(msg,LM._LogExtra(*sr,exc=he,url=req_str,rty=retry))
					LDSAPI.sleepIncr(retry)
					continue
				elif retry:
					# I'm leaving this code here to test with because LDS was  
					# somehow throwing exceptions as well as redirecting
					#
					#if re.search('301',str(he)):
					#	msg = 'Redirect Error {0}'.format(he)
					#	#if we have a valid response and its a 301 see if it contains a redirect-to
					#	if handle and handle.geturl(): 
					#		retry = 1
					#		self.setRequest(handle.geturl()) #TODO reauth?
					#		msg += '. Attempting alternate connect'
					#	else:
					#		retry = 0
					#	LM.error(msg,LM._LogExtra(*sr,exc=he,url=self.getRequestStr(),rty=0))
					#	continue
					if re.search('401|500',str(he)):
						msg = 'HTTP Error {0} Returns {1}. Attempt {2}'.format(req_str,he,MAX_RETRY_ATTEMPTS-retry)
						LM.error(msg,LM._LogExtra(*sr,exc=he,url=req_str,rty=retry))
						continue
					elif re.search('403',str(he)):
						msg = 'HTTP Error {0} Returns {1}. Attempt {2} (consider proxy)'.format(req_str,he,MAX_RETRY_ATTEMPTS-retry)
						LM.error(msg,LM._LogExtra(*sr,exc=he,url=req_str,rty=retry))
						continue
					elif re.search('502',str(he)):
						msg = 'Proxy Error {0} Returns {1}. Attempt {2}'.format(req_str,he,MAX_RETRY_ATTEMPTS-retry)
						LM.error(msg,LM._LogExtra(*sr,exc=he,url=req_str,rty=retry))
						continue
					elif re.search('410',str(he)):
						msg = 'Layer removed {0} Returns {1}. Attempt {2}'.format(req_str,he,MAX_RETRY_ATTEMPTS-retry)
						LM.error(msg,LM._LogExtra(*sr,exc=he,url=req_str,rty=retry))
						retry = 0
						continue
					else:
						msg = 'Error with request {0} returns {1}'.format(req_str,he)
						LM.error(msg,LM._LogExtra(*sr,exc=he,url=req_str,rty=retry))
						continue
				else:
					#Retries have been exhausted, raise the active httpexception
					raise HTTPError(he.msg+msg)
			except HttpResponseError as rd:
				LM.warning('Disconnect. {}'.format(rd),
					LM._LogExtra(*sr,exc=rd,url=req_str,rty=retry))
				LDSAPI.sleepIncr(retry)
				continue
			except URLError as ue:
				LM.warning('URL error on connect {}'.format(ue),
					LM._LogExtra(*sr,exc=ue,url=req_str,rty=retry))
				if re.search('Connection refused|violation of protocol',str(ue)):
					LDSAPI.sleepIncr(retry)
				continue
				#raise ue
			except ConnectionError as ce:
				LM.warning('Error on connection. {}'.format(ce),
					LM._LogExtra(*sr,exc=ce,url=req_str,rty=retry))
				LDSAPI.sleepIncr(retry)
				continue
			except ValueError as ve:
				LM.error('Value error on connect {}'.format(ve),LM._LogExtra(*sr,exc=ve,url=req_str,rty=retry))
				raise ve
			except Exception as xe:
				LM.error('Other error on connect {}'.format(xe),LM._LogExtra(*sr,exc=xe,url=req_str,rty=retry))
				raise xe
		else:
			raise last_exc
		#except Exception as e:
		#	print e
		
# 	def _testalt(self,ref='basic'):
# 		p = os.path.join(os.path.dirname(__file__),cxf or LDSAPI.ath[ref])
# 		self.setAuthentication(Authentication.creds,p, ref)
		
	@staticmethod
	def encode_auth(auth):
		'''Build and b64 encode a http authentication string. [Needs to be bytes str, hence en/decode()]'''
		if 'domain' in auth:
			astr = '{d}\{u}:{p}'.format(u=auth['user'], p=auth['pass'], d=auth['domain']).strip().encode()
		else:
			astr = '{u}:{p}'.format(u=auth['user'], p=auth['pass']).strip().encode()
		return base64.b64encode(astr).decode()
		
	def fetchPages(self,psub=''):
		sr = self.__sec,'Page fetch'
		upd = []
		page = 0
		pagel = None
		morepages = True
		while morepages:
			page = page + 1
			pstr = psub+'&page={0}'.format(page)
			try:
				res = self.connect(plus=pstr)
				if res: self.setResponse(res)
				else: raise HTTPError('No Response using URL {}'.format(pstr))
				#api.dispReq(api.req)
				#api.dispRes(api.res)
			except HTTPError as he:
				LM.error('HTTP Error on page fetch {}'.format(he),LM._LogExtra(*sr,exc=he,url=pstr))
				morepages = False
				raise
				#continue
			except Exception as e:
				#Outer catch of unknown errors
				LM.error('Error on page fetch {}'.format(he),LM._LogExtra(*sr,exc=he,url=pstr))
				raise
			# The logic here is a bit redundant but basically if no last page found then its prob the last page
			# otherwise save the last page value and compare to current page. If they're equal get off loop
			if 'page-last' in self.head: 
				pagel = self.head['page-last']['p']
			else:
				morepages = False
				
			if page == pagel:
				morepages = False
			
			jdata = json.loads(self.respdata.decode())
			upd += [jdata,] if isinstance(jdata,dict) else jdata
					
		return upd
	
	@staticmethod
	def sleepIncr(r):
		t = (INIT_MAX_RETRY_ATTEMPTS-r)*SLEEP_RETRY_INCR
		print('tock' if t%2 else 'tick',t,'{}/{}'.format(r,INIT_MAX_RETRY_ATTEMPTS))
		time.sleep(t)
		
	@staticmethod
	def dispReq(req):
		print ('Request\n-------\n')
		print (LDS.kmask(req.get_full_url()),'auth',req.get_header('Authorization'))
		
	@staticmethod
	def dispRes(res):
		print ('Response\n--------\n')
		print (res.info())
		
	@staticmethod
	def dispJSON(res):
		for l in json.loads(res.read()):
			print ('{0} - {1}\n'.format(l[0],l[1]))
			
	@staticmethod
	def _populate(data):
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
						 'dgt_groups'	   :'/services/api/v1/groups',
						 'dgt_users'	   :'/services/api/v1/users',
						 'dpt_layers'	   :'/services/api/v1/layers/',
						 'dpt_tables'	   :'/services/api/v1/tables/',
						 'dpt_groups'	   :'/services/api/v1/groups',
						 'dpt_users'	   :'/services/api/v1/users',
						 'dgt_draftlayers'  :'/services/api/v1/layers/drafts/',
						 'dgt_drafttables'  :'/services/api/v1/tables/drafts/'},
				  'detail':
						{'dgt_layers'	   :'/services/api/v1/layers/{id}/',
						 'dgt_tables'	   :'/services/api/v1/tables/{id}/',
						 'dgt_groups'	   :'/services/api/v1/groups/{id}/',
						 'dgt_users'	   :'/services/api/v1/users/{id}/',
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
		
	def setParams(self, sec='list', pth='dgt_data', host=LDSAPI.url_def, fmt='json', id=None, version=None, type=None):
		super(DataAPI,self).setCommonParams(host=host,fmt=fmt,sec=sec,pth=pth)
		
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
		
	def setParams(self,sec='list',pth='sgt_sources',host='lds-l',fmt='json',id=None,type=None,source_id=None,scan_id=None,datasource_id=None):
		super(DataAPI,self).setCommonParams(host=host,fmt=fmt,sec=sec,pth=pth)

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
		
	def setParams(self,sec='list',pth='rgt_disp',h='lds-l',fmt='json',id=None,redaction=None):
		super(DataAPI,self).setCommonParams(host=h,fmt=fmt,sec=sec,pth=pth)
		
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


	def readLayerPages(self):
		'''Calls API custom page reader'''
		self.api.setParams(sec='list',pth=self.lpath,host=self.uref)
		return self.api.fetchPages()
		
	def readAllLayerIDs(self):
		'''Extracts and returns IDs from reading layer-pages'''
		return [p['id'] for p in self.readLayerPages() if 'id' in p]		
	
	def readGroupPages(self):
		'''Calls API custom page reader'''
		self.api.setParams(sec='list',pth=self.gpath,host=self.uref)
		return self.api.fetchPages()
		
	def readAllGroupIDs(self):
		'''Extracts and returns IDs from reading group-pages'''
		return [p['id'] for p in self.readGroupPages() if 'id' in p]	
	
	
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
		'''get requested URL using specified defs'''
		uref = uref or cls.UREF
		pref = pref or cls.PREF
		if isinstance(korb,dict):
			return cls._get(uref,pref,korb,cxf) 
		elif korb and korb.lower() in ['key','basic']:
			aref = korb.lower()
		else: 
			aref = cls.AREF
		method = (Authentication.creds,cxf or LDSAPI.ath[aref]) if aref=='basic' else (Authentication.apikey,cxf or LDSAPI.ath[aref])
		
		da = DataAccess(*method,uref=uref,pref=pref,aref=aref)
		return da.api.conn(uref)
		#return res or da.api.getResponse()['data']
		
	@classmethod
	def _get(cls,uref=None,pref=None,korb={},cxf=None):
		'''korb must be a dict containing {'key':'ABC...','up':['user','pass'],'kfile':'apikey','cfile':'creds'}'''
		kk0 = list(korb.keys())[0]
		kd = {
			'key'	:(Authentication.direct,'key'),
			'up'	:(Authentication.direct,'basic'),
			'kfile'	:(Authentication.apikey,'key'),
			'cfile'	:(Authentication.creds, 'basic')
		}
		da = DataAccess(kd[kk0][0],korb[kk0],uref=uref,pref=pref,aref=kd[kk0][1])
		return da.api.conn(uref)
	
	#unnecessary since only classmethods
	def __enter__(self):
		return self
	
	def __exit__(self, type, value, traceback):
		pass
		
class DataAccess(APIAccess):
	'''Convenience class for accessing commonly needed data-api data'''
	
	PAGES = ('data','permission','group')
	LAYER_PAGES = ('data','permission')
	GROUP_PAGES = ('group',)
	
	def __init__(self, creds, cfile, uref=LDSAPI.url_def, pref=LDSAPI.pxy_def, aref=LDSAPI.ath_def):
		super(DataAccess, self).__init__(DataAPI, creds, cfile, (uref, pref, aref))
		self.path = 'dgt_layers'
		self.lpath = 'dgt_layers'
		self.gpath = 'dgt_groups'
		self.ppath = 'dgt_permissions'
		
	def _set(self,l,nl=None):
		'''fetch if value present in path and returns utf encoded'''
		if nl: 
			for ni in nl:
				if l and (ni in l or (isinstance(ni,int) and isinstance(l,(list,tuple)))):
					l = l[ni]
				else:
					l = None
		if isinstance(l, string_types):
			return l.encode('utf-8')
		else:
			return l 
		#if n2: return l[n1][n2].encode('utf8') if n1 in l and n2 in l[n1] else None
		#else: return l[n1].encode('utf8') if n1 in l else None
	
	def readLayerFields(self,i):
		'''All field from detail layer pages'''
		self.api.setParams(sec='detail',pth=self.lpath,host='lds-l',id=i)
		return self.api.fetchPages()[0]
	
	def readGroupFields(self,i):
		'''All field from detail group pages'''
		self.api.setParams(sec='detail',pth=self.gpath,host='lds-l',id=i)
		return self.api.fetchPages()[0]
	
	def readPermissionFields(self,i,gfilter=True):
		'''All field from permission pages, filter by group.everyone i.e. accessible'''
		self.api.setParams(sec='access',pth=self.ppath,host='lds-l',id=i)
		pge = [p for p in self.api.fetchPages() if not gfilter or p['id']=='group.everyone']
		return pge[0] if pge else None
		
	
	def readLayers(self): return self._readFields(idfunc=self.readAllLayerIDs,pagereq=self.LAYER_PAGES)
	#def readLayers(self): return self._readFields(idfunc=self._testLayerList,pagereq=self.LAYER_PAGES)
	#def _testLayerList(self): return [52109,51779]
	def readGroups(self): return self._readFields(idfunc=self.readAllGroupIDs,pagereq=self.GROUP_PAGES)
	#def readGroups(self): return self._readFields(idfunc=self._testGroupList,pagereq=self.GROUP_PAGES)
	#def _testGroupList(self): return [2006,2115]
									
	def _readFields(self,idfunc,pagereq):
		'''Read the fields from selected (predefined) pages'''
		detail,herror = {},{}		
		for i in idfunc():
			#print ('WARNING. READING LDS-API-ID SUBSET',i)
			detail[str(i)],herror[str(i)] = self._readDetail(i,pagereq)
		return detail,herror

	def _readDetail(self,i,pr):
		'''INPROGRESS Attempt to consolidate the readX functions'''
		dd,he = {},None
		fun_det = {
				'data':(self.readLayerFields,
						{'id':('id',),'title':('title',),'type':('type',),'group':('group','id'),'kind':('kind',),'cat':('categories',0,'slug'),'crs':('data','crs'),\
						'grp-id':('group','id'),'grp-nm':('group','name'),\
						'lic-id':('license','id'),'lic-ttl':('license','title'),'lic-typ':('license','type'),'lic-ver':('license','version'),\
						'data-crs':('data','crs'),'data-pky':('data','primary_key_fields'),'data-geo':('data','geometry_field'),'data-fld':('data','fields'),\
						'date-pub':('published_at',),'date-fst':('first_published_at',),'date-crt':('created_at',),'date-col':('collected_at',)
				  }),
				'permission':(self.readPermissionFields,
						{'prm-id':('id',),'prm-typ':('permission',),'prm-gid':('group','id',),'prm-gnm':('group','name')}),
				'group':(self.readGroupFields,
						{'grp-id':('id',),'grp-name':('name',),'grp-lyrs':('stats','layers',),'grp-tbls':('stats','tables'),'grp-docs':('stats','documents')})
				}
		for fd in set(fun_det.keys()).intersection(pr):
			#fetch the requested pages
			try:
				d = fun_det[fd][0](i)
			except HTTPError as he:
				LM.error('HTTP Error on selectedFields data '+he,LM._LogExtra('LArsf','dhe',xid=i))
				return
			#put the results into a dict
			try:
				dd.update( {k:self._set(d,fun_det[fd][1][k]) for k in fun_det[fd][1]} if d else {d:None for d in fun_det[fd][1]} )
				#special postprocess
				if fd == 'data':
					dd['data-pky'] = self._set(','.join(dd['data-pky']))  
					dd['data-fld'] = self._set(','.join([f['name'] for f in dd['data-fld']]))
			except IndexError as ie:
				#not raising this as an error since it only occurs on 'test' layers
				msg = '{0}. Index error getting {1},{2}'.format(ie,d['id'],d['name'])
				LM.error(msg,LM._LogExtra('LArsf','die',xid=i))
			except TypeError as te:
				msg = '{0}. Type error on layer {1}/{2}'.format(te,d['id'],d['name'])
				LM.error(msg,LM._LogExtra('LArsf','dte',xid=i))
				return
			except Exception as e:
				msg = '{0}. Error on layer {1}/{2}'.format(e,d['id'],d['name'])
				LM.error(msg,LM._LogExtra('LArsf','de',xid=i))
				raise
			
		return dd,he

	
# 	def _readDetailGroup(self,i):
# 		he = None
# 		try:
# 			#returns the permissions for group.everyone only
# 			g = self.readGroupFields(i)
# 		except HTTPError as he:
# 			LM.error('HTTP Error on selectedFields group '+he,LM._LogExtra('LArsf','phe',xid=i))
# 			return
# 		
# 		try:
# 			gx = {'grp-name':('name',),'grp-lyrs':('stats','layers',),'grp-tbls':('group','tables'),'grp-docs':('group','documents')}
# 			gg = {k:self._set(g,gx[k]) for k in gx} if g else {g:None for g in gx}
# 
# 		except IndexError as ie:
# 			#not raising this as an error since it only occurs on 'test' layers
# 			msg = '{0} error getting {1},{2}'.format(ie,i,g['name'])
# 			LM.error(msg,LM._LogExtra('LArsf','gie',xid=i))
# 		except TypeError as te:
# 			msg = '{0} error on layer {1}/{2}'.format(te,i,g['name'])
# 			LM.error(msg,LM._LogExtra('LArsf','gte',xid=i))
# 			return
# 		except Exception as e:
# 			msg = '{0} error on layer {1}/{2}'.format(e,g['id'],g['name'])
# 			LM.error(msg,LM._LogExtra('LArsf','ge',xid=i))
# 			raise
# 		
# 		return gg,he
	
	def _readSummaryPages2(self,pagereq=('data','group')):
		'''IN_PROGRESS Sometimes we don't need to get the detail pages. Just extract the summary'''
		detail = {}
		herror = {}

		if 'data' in pagereq:
			d,dh = self._readSummaryData()
			detail.update(d)
			if dh: herror += dh
			
		if 'group' in pagereq:
			d,dh = self._readSummaryGroup()
			detail.update(d)
			if dh: herror += dh
			
		return detail,herror
		
	def readPrimaryKeyFields(self):
		'''Read PrimaryKey field from detail pages'''
		res,_ = self.readLayers(pagereq=('data',))
		return res

'''Copied from LDSChecker for availability'''
		
# class AuthenticationException(Exception):pass
# class Authentication(object):
# 	'''Static methods to read keys/user/pass from files'''
# 		
# 	@staticmethod
# 	def apikey(keyfile,kk='key',keyindex=None):
# 		'''Returns current key from a keyfile advancing KEYINDEX on subsequent calls (if ki not provided)'''
# 		global KEYINDEX
# 		key = Authentication.searchfile(keyfile,'{0}'.format(kk))
# 		if key: return key
# 		key = Authentication.searchfile(keyfile,'{0}{1}'.format(kk,keyindex or KEYINDEX))
# 		if not key and not keyindex:
# 			KEYINDEX = 0
# 			key = Authentication.searchfile(keyfile,'{0}{1}'.format(kk,KEYINDEX))
# 		elif not keyindex:
# 			KEYINDEX += 1
# 		return key
# 	
# 	@staticmethod
# 	def direct(value):
# 		'''Returns arg for cases where user just wants to submit a key/userpass directly'''
# 		return value
# 		
# 	@staticmethod
# 	def creds(cfile):
# 		'''Read CIFS credentials file'''
# 		return (Authentication.searchfile(cfile,'username'),\
# 				Authentication.searchfile(cfile,'password'),\
# 				Authentication.searchfile(cfile, 'domain'))
# 		
# 	@staticmethod
# 	def userpass(cfile):
# 		return creds(cfile)[:2]
# 			
# 	#@staticmethod
# 	#def userpass(upfile):
# 	#	return (Authentication.searchfile(upfile,'username'),Authentication.searchfile(upfile,'password'))
# 	
# 	@staticmethod
# 	def searchfile(spf,skey,default=None):
# 		'''Given a file name incl path look for the file in the provided path, the home dir and 
# 		the current dir then checks this file for the key/val named in skey'''
# 		#value = default
# 		#look in current then app then home
# 		sp,sf = os.path.split(spf)
# 		spath = (sp,'',os.path.expanduser('~'),os.path.dirname(__file__))
# 		verified = [os.path.join(p,sf) for p in spath if os.path.lexists(os.path.join(p,sf))]
# 		if not verified:
# 			LM.error('Cannot find file '+sf,LM._LogExtra('LAAs','sf'))
# 			raise AuthenticationException('Cannot find requested file {}'.format(sf))
# 		with open(verified[0],'r') as h:
# 			for line in h.readlines():
# 				k = re.search('^{key}=(.*)$'.format(key=skey),line)
# 				if k: return k.group(1)
# 		return default
# 	
# 	@staticmethod
# 	def getHeader(korb,kfile):
# 		'''Convenience method for auth header'''
# 		if korb.lower() == 'basic':
# 			b64s = base64.encodestring('{0}:{1}'.format(*Authentication.userpass(kfile))).replace('\n', '')
# 			return ('Authorization', 'Basic {0}'.format(b64s))
# 		elif korb.lower() == 'key':
# 			key = Authentication.apikey(kfile)
# 			return ('Authorization', 'key {0}'.format(key))
# 		return None # Throw something

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
		#print sa.readAllLayerIDs()
		res = sa.readLayerPages()
		lsaids = [(r['id'],r['last_scanned_at']) for r in res if r['last_scanned_at']]
		for lid,dt in lsaids:
			print ('layer {} last scanned at {}'.format(lid,dt))	
			
	def _testDA(self):
		da = DataAccess(creds,self.credsfile)
		#print sa.readAllLayerIDs()
		res = da.readPrimaryKeyFields()
		print(res)
		
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

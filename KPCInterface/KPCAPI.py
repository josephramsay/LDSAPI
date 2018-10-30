'''
Created on 11/11/2015

@author: jramsay
'''
        
#from APIInterface.LDSAPI2 import DataAccess
import re
import os
import pickle

from collections import namedtuple
from KPCInterface.AuthReader import Authentication

LDS_LIVE = 'data.linz.govt.nz'
LDS_TEST = 'data-test.linz.govt.nz'

RELOAD_INDEX = False
CONF = 'rbu.conf'


LayerInfo = namedtuple('LayerInfo', 'title id version versions dates files')

class LayerRef(object):
    layeridmap = {}
    
    def __init__(self,client,reload):
        #init name and id refs
        self.client = client
        if reload or RELOAD_INDEX or not self._load():
            self._indexLayers()
            self._dump()
        
    def _indexLayers(self, stype='catalog'):
        '''query the catalog/layer obj for layer name id pairs returning dict indexed by name (for easier metadata matching)'''
        #NB. Catalog layers not necessarily complete
        lsrc = self.client.catalog.list if stype=='layer' else self.client.layers.list
        #for i in self.client.catalog.list(): print('CL',i)
        #for i in self.client.layers.list(): print('LL',i)
        for ly in lsrc():#.filter(type='layer')[:10]:
            print('Ly',ly) 
            dd = {'cpub':getattr(ly,'published_at',None), 
                  'fpub':getattr(ly,'first_published_at',None),
                  'crt':getattr(ly,'created_at',None),
                  'col':getattr(ly,'collected_at',None)}
            self.layeridmap[ly.title] = LayerInfo(title=ly.title,id=ly.id,version=ly.version,versions=[x.id for x in ly.list_versions()],dates=dd, files=())
            
    def _dump(self, config=CONF):
        pickle.dump(self.layeridmap,open(config,'wb'))
        
    def _load(self, config=CONF):
        try:
            self.layeridmap = pickle.load(open(config,'rb'))
        except:
            return False
        return True

    
# class Authentication(object):
#     '''Static methods to read keys/user/pass from files'''
# 
#     
#     @staticmethod
#     def userpass(upfile):
#         return (Authentication.searchfile(upfile,'username'),Authentication.searchfile(upfile,'password'))
#         
#     @staticmethod
#     def _apikey(kfile,kk='key'):
#         '''Returns current key from a keyfile advancing on subsequent calls'''
#         global KEYINDEX
#         key = Authentication.searchfile(kfile,'{0}{1}'.format(kk,KEYINDEX))
#         if not key:
#             KEYINDEX = 0
#             key = Authentication.searchfile(kfile,'{0}{1}'.format(kk,KEYINDEX))
#         else:
#             KEYINDEX += 1
#         return key
#     
#     @staticmethod
#     def _creds(cfile):
#         '''Read CIFS credentials file'''
#         return (Authentication.searchfile(cfile,'username'),\
#                 Authentication.searchfile(cfile,'password'),\
#                 Authentication.searchfile(cfile,'domain','WGRP'))
#     
#     @staticmethod
#     def searchfile(sfile,skey,default=None):
#         value = default
#         #look in current then app then home
#         spath = (os.path.dirname(__file__),os.path.expanduser('~'))
#         first = [os.path.join(p,sfile) for p in spath if os.path.exists(os.path.join(p,sfile))][0]
#         with open(first,'r') as h:
#             for line in h.readlines():
#                 k = re.search('^{key}=(.*)$'.format(key=skey),line)
#                 if k: value=k.group(1)
#         return value
# 
#     @staticmethod
#     def apikey():
#         return Authentication._apikey(os.path.join(os.path.expanduser('~'),KEY_FILE),'admin')
#     
#     @staticmethod
#     def creds(): 
#         #upd
#         return Authentication._creds(os.path.join(os.path.expanduser('~'),AD_CREDS))



   

'''
Created on 23/12/2013

@author: jramsay
'''

#https://koordinates.com/services/api/v1/sources/1/

import unittest
import json
import os



from APIInterface.LDSAPI import DataAPI
#from APIInterface.LDSAPI import SourceAPI
#from APIInterface.LDSAPI import RedactionAPI
from .TestFileReader import FileReader
from .TestSuper import APITestCase


ID = 455
VER = 460
TYP = 'iso'
FMT = 'json'

class DataTester(APITestCase):
    
    avoid = ['dpu_draftversion','ddl_delete']
    
    def setUp(self):
        print('D')#\n----------------------------------\n'
        self.api = DataAPI(FileReader.creds,self.cdir+self.cfile)
        self.api.setParams()
        
    def tearDown(self):
        self.api = None
        
    #basic connect
    
    def test_10_ReadBaseData(self):
        self.api.connect()
        self.api.dispRes(self.api.res)
    
    #parameter sets test
    
        
    def test_20_DataAPI_list(self):
        sec='list'
        for pth in list(self.api.data_path[sec].keys()):
            print('*** Data API section={} key={} ***'.format(sec,str(pth)))
            self.api.setParams(s=sec,p=pth)
            self.api.connect('?format={}'.format(FMT))
            print('*** {}'.format(self.api.req.get_full_url()))
            self.outputRes(self.api.res.read())    
            
    def test_30_DataAPI_detail(self):
        sec = 'detail'
        for pth in list(self.api.data_path[sec].keys()):
            if pth in self.avoid: continue
            print('*** Data API section={} key={} ***'.format(sec,str(pth)))
            self.api.setParams(s=sec,p=pth,id=ID)
            self.api.connect('?format={}'.format(FMT))
            print('*** {}'.format(self.api.req.get_full_url()))
            self.outputRes(self.api.res.read())    
             
    def test_40_DataAPI_version(self):
        sec = 'version'
        for pth in list(self.api.data_path[sec].keys()):
            if pth in self.avoid: continue
            print('*** Data API section={} key={} ***'.format(sec,str(pth)))
            self.api.setParams(s=sec,p=pth,id=ID,version=VER)
            self.api.connect('?format={}'.format(FMT))
            print('*** {}'.format(self.api.req.get_full_url()))
            self.outputRes(self.api.res.read())
             
#     def test_50_DataAPI_publish(self):
#         sec = 'publish'
#         for pth in self.api.data_path[sec].keys():
#             if pth in self.avoid: continue
#             print '*** Data API section={} key={} ***'.format(sec,str(pth))
#             self.api.setParams(s=sec,p=pth,id=ID)
#             self.api.connect('?format=json')
#             print '*** {}'.format(self.api.req.get_full_url())
#             self.outputRes(self.api.res.read())
             
    def test_60_DataAPI_metadata(self):
        sec = 'metadata'
        for pth in list(self.api.data_path[sec].keys()):
            if pth in self.avoid: continue
            print('*** Data API section={} key={} ***'.format(sec,str(pth)))
            self.api.setParams(s=sec,p=pth,id=ID,version=VER,type=TYP)
            self.api.connect('?format={}'.format(FMT))
            print('*** {}'.format(self.api.req.get_full_url()))
            self.outputRes(self.api.res.read())
        
  

    def outputRes(self,res):
        be = json.loads(res)
        print('JSON - start')
        if isinstance(be, dict):
            self.outputFeat(be)
        else:
            for l in be: self.outputFeat(l)
        print('JSON - end')
        
    def outputFeat(self,feat):
        print('name:{} - id:{} type:{} published:{}'.format(feat['name'],feat['id'],feat['type'],feat['published_at']))    
            
    
if __name__ == '__main__':
    unittest.main()
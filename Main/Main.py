'''
Created on 14/01/2014

@author: jramsay
'''
import json
import sys
import os

from APIInterface.LDSAPI import SourceAPI
from APIInterface.LDSAPI import DataAPI
from APIInterface.LDSAPI import RedactionAPI

from .Main import CReader
from APIInterface.RFC import RFC2388, RequestGenerator

cat = []

#example on apiary
#values = "--b0017bc3bab14fed95910bfcc4a1ddd8\nContent-Disposition: form-data; name=\"abc\"; filename=\"points-of-interest.zip\"\nContent-Type: application/x-zip\n\n(binary data not shown)\n--b0017bc3bab14fed95910bfcc4a1ddd8\nContent-Disposition: form-data; name=\"source\"\nContent-Type: application/json\n\n{\n    \"name\": \"points-of-interest\", \n    \"type\": \"upload\", \n    \"user\": 3\n}\n--b0017bc3bab14fed95910bfcc4a1ddd8--"
#headers = {"Content-Type": "multipart/form-data; boundary=b0017bc3bab14fed95910bfcc4a1ddd8"}
#request = Request("https://private-c694-sources1.apiary.io/services/api/v1/sources/", data=values, headers=headers)
#response_body = urlopen(request).read()

v0 = json.dumps({
    "name": "A random dir with Shapefiles",
    "type": "arcgis",
    "description": "Assorted Test Tables", 
    "categories": [], 
    "user": 3,
    "options": {
        "username": "<username>",
        "password": "<pasword>"
    },
    "url_remote": "https://127.0.0.1/postgis/rest/services",
    "scan_schedule": "@daily"
})


h1 = ("Content-Type", "application/json")
v1 = json.dumps({
    "name": "Local PG Test server",
    "type": "postgis",
    "description": "Assorted Test Tables", 
    "categories": [], 
    "user": 3,
    "options": {
        "username": "<username>",
        "password": "<pasword>"
    },
    "url_remote": "https://127.0.0.1/postgis/rest/services",
    "scan_schedule": "@daily"
})



h2 = ("Content-Type", "multipart/form-data; boundary=b0017bc3bab14fed95910bfcc4a1ddd8")
v2 = "--b0017bc3bab14fed95910bfcc4a1ddd8\nContent-Disposition: form-data; name=\"abc\"; filename=\"points-of-interest.zip\"\nContent-Type: application/x-zip\n\n(binary data not shown)\n--b0017bc3bab14fed95910bfcc4a1ddd8\nContent-Disposition: form-data; name=\"source\"\nContent-Type: application/json\n\n{\n    \"name\": \"points-of-interest\", \n    \"type\": \"upload\", \n    \"user\": 3\n}\n--b0017bc3bab14fed95910bfcc4a1ddd8--"


class APIOperation(object):
    pass
#    
#     def setParams(self,args):
#         @functools.wraps(args)
#         def wrapper(*args, **kwargs):
#             self.api.setParams(**dict((k,v) for (k,v) in self.params.iteritems() if not v is None))
        
class Query(APIOperation):
    '''
    classdocs
    '''


    def __init__(self):
        self.api = DataAPI()
        self.cr = CReader('../APIInterface/sampledata')
    
    def probe(self):
        self.api.connect()
        self.api.dispReq(self.api.req)
        self.api.dispRes(self.api.res)
        
class Redact(APIOperation):
    '''
    classdocs
    '''

    def __init__(self):
        self.api = RedactionAPI()
        self.cr = CReader('../APIInterface/sampledata')
    
    def probe(self):
        self.api.connect()
        self.api.dispReq(self.api.req)
        self.api.dispRes(self.api.res)
        
        
class Publish(APIOperation):
    '''
    classdocs
    '''


    def __init__(self):
        self.api = SourceAPI()
        self.cr = CReader('../APIInterface/sampledata')
    
    def probe(self):
        self.api.connect()
        self.api.dispReq(self.sa.req)
        self.api.dispRes(self.sa.res)
        
    def setSRC(self):
        self.api.connect(head=self.cr.readSecOpt('fakedata1', 'header'), data=self.cr.readSecOpt('fakedata1', 'data'))
        ll = json.loads(self.api.res.read())
        print(ll)    
        
    def pushSRC(self):
        self.api.connect(head=self.cr.readSecOpt('fakedata2', 'header'), data=self.cr.readSecOpt('fakedata2', 'data'))
        ll = json.loads(self.api.res.read())
        print(ll)

    def buildContent(self):
        p = self.cr.readArcGISSection('agdata')
        c = RequestGenerator.buildContentArcGIS(p['uname'],p['sname'],p['ctype'],p['desc'],p['cats'],p['url'],p['opts'],p['scan'])
        print(c)
        
        q = self.cr.readArcGISSection('pgdata')
        d = RequestGenerator.buildContentArcGIS(q['uname'],q['sname'],q['ctype'],q['desc'],q['cats'],q['url'],q['opts'],q['scan'])
        print(d)
        
        rfc = RFC2388()
        head = rfc.headGenerator()
        data = rfc.dataGenerator((c,d))
        print(head)
        print(data)
        
        return head,data
    
    def buildContentArcGIS(self,url,opts):
        return 'url_remote={}'.format(url)

def test():
    rc = Redact()
    rc.api.setParams(id=319)
    rc.probe()    
    
    #rc.api.setParams(p='rgt_info')
    #rc.probe()  
    
    #rc.api.setParams(p='rgt_info',id=123,redaction=789)
    #rc.probe()    
    
#     dc = Query()
#     dc.probe()
#     
#     pc = Publish()
#     pc.buildContent()
#     pc.probe()
#     #pc.setSRC()
#     #pc.pushSRC()
    
def main():
    test()
    
if __name__ == "__main__":
    sys.exit(main())
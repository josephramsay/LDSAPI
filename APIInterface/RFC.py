'''
Created on 16/01/2014

@author: jramsay
'''

import string
import random
import json
from Main import CReader

BLEN=70
BCHARS = string.ascii_lowercase+string.digits#+string.punctuation
#BCHARS = 'abcdefghijklmnopqrstuvwxyz0123456789()+_,-./:=?\''


#header=("Content-Type", "multipart/form-data; boundary=b0017bc3bab14fed95910bfcc4a1ddd8")
#data="--b0017bc3bab14fed95910bfcc4a1ddd8\nContent-Disposition: form-data; name=\"abc\"; filename=\"points-of-interest.zip\"\nContent-Type: application/x-zip\n\n(binary data not shown)\n--b0017bc3bab14fed95910bfcc4a1ddd8\nContent-Disposition: form-data; name=\"source\"\nContent-Type: application/json\n\n{\n    \"name\": \"points-of-interest\", \n    \"type\": \"upload\", \n    \"user\": 3\n}\n--b0017bc3bab14fed95910bfcc4a1ddd8--"

class RFC2388(object):
    
    def __init__(self):
        '''Constructor'''
        self.cr = CReader('../APIInterface/sampledata')
        self.boundary = RFC2388.boundaryGenerator()
    
    def headGenerator(self):

        name = 'Content-Type'
        desc = 'multipart/form-data; boundary={}'.format(self.boundary)
        
        return (name,desc)
        
    def dataGenerator(self,content):
        data = self.boundary+'\n'
        for block in content:
            data += block+'\n'
            data += self.boundary+'\n'
        return data
    

    @staticmethod
    def boundaryGenerator(length=BLEN,chars=BCHARS):        
        return ''.join([random.choice(chars) for x in range(length)])


class RequestGenerator(object):
    pCDmfd = 'Content-Disposition: multipart/form-data;'
    pCDfd = 'Content-Disposition: form-data;'
    
    pName = 'name="{}"'
    pType = 'type="{}"'
    pDesc = 'description="{}"'
    pCats = 'categories="{}"'
    pFile = 'filename="{}"'
    pUser = 'user={}'
    pOpts = 'options={}'
    pURL  = 'url_remote={}'
    pScan = 'scan_schedule={}'
    pCTaz = 'Content-Type: application/x-zip'
    pCTaj = 'Content-Type: application/json'
    
    def __init__(self,params):
        '''Constructor'''
        pass
    
    
    def buildContent(self):
        pass
        #c = RequestGenerator.contentFormatterJSON(name, type, user, jdata)
    
    @classmethod
    def buildOptionsList(cls,opts):
        return json.dumps(opts)
        
    
    @classmethod
    #                          user  src   content
    def buildContentArcGIS(cls,uname,sname,ctype,desc,cats,url,opts,scan):
        return '\n'.join((
                        cls.pCDfd,
                        cls.pCTaz,
                        cls.pName.format(sname),
                        cls.pType.format(ctype),
                        cls.pDesc.format(desc),
                        cls.pCats.format(cats),                      
                        cls.pUser.format(uname),
                        cls.pOpts.format(RequestGenerator.buildOptionsList(opts)),
                        cls.pScan.format(scan),
                        cls.pURL.format(url)))    
        
    @classmethod
    def buildContentPostGIS(cls,uname,sname,ctype,desc,cats,url,opts,scan):
        return '\n'.join((
                        cls.pCDfd,
                        cls.pCTaz,
                        cls.pName.format(sname),
                        cls.pType.format(ctype),
                        cls.pDesc.format(desc),
                        cls.pCats.format(cats),                      
                        cls.pUser.format(uname),
                        cls.pOpts.format(RequestGenerator.buildOptionsList(opts)),
                        cls.pScan.format(scan),
                        cls.pURL.format(url)))    
        
    @classmethod
    def buildContentCIFS(cls,uname,sname,ctype,desc,cats,url,opts,scan):
        return '\n'.join((
                        cls.pCDfd,
                        cls.pCTaz,
                        cls.pName.format(sname),
                        cls.pType.format(ctype),
                        cls.pDesc.format(desc),
                        cls.pCats.format(cats),                      
                        cls.pUser.format(uname),
                        cls.pOpts.format(RequestGenerator.buildOptionsList(opts)),
                        cls.pScan.format(scan),
                        cls.pURL.format(url)))
    
    
    @classmethod
    def buildContentURL(cls,uname,sname,ctype,desc,cats,url,opts,scan):
        return '\n'.join((
                        cls.pCDfd,
                        cls.pCTaz,
                        cls.pName.format(sname),
                        cls.pType.format(ctype),
                        cls.pDesc.format(desc),
                        cls.pCats.format(cats),                      
                        cls.pUser.format(uname),
                        cls.pOpts.format(RequestGenerator.buildOptionsList(opts)),
                        cls.pScan.format(scan),
                        cls.pURL.format(url)))
    
    @classmethod
    def contentFormatterBinary(cls,name,fname,raw):
        return '\n'.join(cls.pCD,cls.pName.format(name),cls.pFile.format(fname),cls.pCTz,raw)
        
    @classmethod
    def contentFormatterJSON(cls,name,otype,user,jdata):
        return '\n'.join(cls.pCD,cls.pName.format(name),cls.ptype.format(otype),cls.pUser.format(user),cls.pCTj,jdata)
    
    
    
    
            
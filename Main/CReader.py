'''
Created on 6/01/2014

@author: jramsay
'''
from configparser import ConfigParser, NoSectionError, NoOptionError, ParsingError,  Error
import re

class CReader(object):
    '''
    Simple config file reader
    '''


    def __init__(self,fn):
        '''
        Constructor
        '''
        self.fn = fn
        self.cp = ConfigParser()
        self.cp.read(fn)
    
     
    def listSections(self):
        return self.cp.sections()
    
    def hasSection(self,secname):
        return secname in self.getSections()
    
    def getSections(self):
        return self.cp.sections()
    
    def _readSec(self,sec,opts):
        ovdic = {}
        for o in opts:
            try:
                val = self.cp.get(sec,str(o))
            except NoSectionError:
                print('No Sec',sec)
                raise
            except NoOptionError as noe:
                print('No Opt',str(o))
                raise
            ovdic[str(o)] = val
        return ovdic
        
    def readHDSection(self,secname):
        return self._readSec(secname,('header','data'))
    
    def readUPSection(self,secname):
        return self._readSec(secname,('user','pass'))
    
    def readArcGISSection(self,secname):
        return self._readSec(secname,('uname','sname','ctype','desc','cats','url','opts','scan'))
    
    def readSecOpt(self,sec,opt):
        return self.cp.get(sec, opt)
    
    
class FileReader(object):

    def __init__(self):
        pass
    
    def userpass(self,upfile):
        return (self.searchfile(upfile,'username'),self.searchfile(upfile,'password'))

    def hostport(self,upfile):
        return (self.searchfile(upfile,'host','127.0.0.1'),self.searchfile(upfile,'port','5432'))

    def apikey(self,kfile):
        return self.searchfile(kfile,'key')

    def creds(self,cfile):
        '''Template Read-Credentials function'''
        return (self.searchfile(cfile,'username'),self.searchfile(cfile,'password'),self.searchfile(cfile,'domain','WGRP'))
    
    def searchfile(self,sfile,skey,default=None):
        '''Template key-val file reader '''
        value = default
        with open(sfile,'r') as h:
            for line in h.readlines():
                k = re.search('^{key}=(.*)$'.format(key=skey),line)
                if k: value=k.group(1)
        return value    
        

        

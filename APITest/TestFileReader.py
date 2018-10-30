'''
Created on 6/06/2014

@author: jramsay
'''
import re,os
    
class FileReader(object):

    def __init__(self):
        pass
    
    @classmethod
    def creds(cls,cfile):
        '''Template Read-Credentials function'''
        return (cls.searchfile(cfile,'username'),cls.searchfile(cfile,'password'),cls.searchfile(cfile,'domain','WGRP'))
    
    @classmethod
    def searchfile(cls,sfile,skey,default=None):
        '''Template key-val file reader '''
        value = default
        with open(sfile,'r') as h:
            for line in h.readlines():
                k = re.search('^{key}=(.*)$'.format(key=skey),line)
                if k: value=k.group(1)
        return value    
        

        

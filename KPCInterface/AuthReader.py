'''
Created on 13/01/2016

@author: jramsay
'''


import os
import re

KEYINDEX = 0
KEY_FILE = '.apikey_ldst'
AD_CREDS = '.credentials'
CREDS = {}
ARCONF = None


class Authentication(object):
    '''Static methods to read keys/user/pass from files'''

    @staticmethod
    def userpass(upfile):
        return (Authentication.searchfile(upfile, 'username'),
                Authentication.searchfile(upfile, 'password'))

    @staticmethod
    def _apikey(kfile, kk='key'):
        '''Returns current key from a keyfile advancing on subsequent calls'''
        global KEYINDEX
        key = Authentication.searchfile(kfile, '{0}{1}'.format(kk, KEYINDEX))
        if not key:
            KEYINDEX = 0
            key = Authentication.searchfile(kfile, '{0}{1}'.format(kk, KEYINDEX))
        else:
            KEYINDEX += 1
        return key

    @staticmethod
    def _creds(cfile):
        '''Read CIFS credentials file'''
        return (Authentication.searchfile(cfile, 'username'),
                Authentication.searchfile(cfile, 'password'),
                Authentication.searchfile(cfile, 'domain', 'WGRP'))

    @staticmethod
    def searchfile(sfile, skey, default=None):
        value = default
        # look in current then app then home
        spath = (os.path.dirname(__file__), os.path.expanduser('~'))
        first = [os.path.join(p, sfile) for p in spath if os.path.exists(os.path.join(p, sfile))][0]
        with open(first, 'r') as h:
            for line in h.readlines():
                k = re.search('^{key}=(.*)$'.format(key=skey), line)
                if k: value = k.group(1)
        return value

    @staticmethod
    def apikey():
        return Authentication._apikey(os.path.join(os.path.expanduser('~'), KEY_FILE), 'admin')

    @staticmethod
    def creds():
        # upd
        return Authentication._creds(os.path.join(os.path.expanduser('~'), AD_CREDS))


class ConfigAuthentication(Authentication):
    '''auth subclass where a configreader object is supplied instead of selected searchable files'''

    def __init__(self,conf):
        self.conf = conf
    
    def creds(self,sect='remote'):
        return (self.conf.d[sect]['user'],
                self.conf.d[sect]['pass'],
                self.conf.d[sect]['workgroup'])

    def userpass(self,sect='remote'):
        return (self.conf.d[sect]['user'], self.conf.d[sect]['pass'])    
    
    def apikey(self,sect='server'):
        '''returns a single know apikey, doesnt do key cycling'''
        return self.conf.d[sect]['key']


                
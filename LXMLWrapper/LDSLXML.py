'''
Created on 16/06/2015

@author: jramsay

This module is a hack wrapping LXML because Py2.6 doesn't support namespaces declarations. This isn't necessary in a 2.7+ env

'''

import re
import sys

PYVER3 = sys.version_info > (3,)

if PYVER3:
    import urllib.request as u_lib
    from urllib.error import HTTPError
else:
    import urllib2 as u_lib
    from urllib2 import HTTPError
    pass

from lxml import etree

class LXMLWrapperException(Exception): pass

class LXMLetree(object):
    def __init__(self):
        pass
        
    def parse(self,content,op='parse'):
        return LXMLtree(content,op)
    
    def fromstring(self,text,op='fromstring'):
        return LXMLtree(text,op)
    
    def XMLSchema(self,xsdd):
        '''return a vanilla schema since no customisation required'''
        return etree.XMLSchema(xsdd)
    
    @classmethod
    def _subNS(cls,url,ns):
        '''Hack for Py2.6 version of LXML to substitute namespace declarations /abc:path for /{full_abc}path'''
        for k in set(re.findall('(\w*?):',url)):
            url = re.sub(k+':','{'+ns[k]+'}',url)
        return url
        
    
class LXMLtree(object):
    '''Wrapper class for etree objects'''
    def __init__(self,ct,op='parse'):
        if op=='parse':
            self._tree = self.parse(ct)
        elif op=='parsestring':
            self._tree = self.parse(ct,p='fromstring')
        elif op=='fromstring':
            self._tree = self.fromstring(ct)
        elif op=='recover':
            self._tree = self.parse(ct,p=etree.XMLParser(recover=True))
        
    def fromstring(self,text):
        '''parses a string to root node'''
        return etree.fromstring(text)
    
    def xpath(self,text,namespaces=None):
        return etree.XPath(text,namespaces) if namespaces and False else etree.XPath(text)
    
    def parse(self,content,p=None):
        '''parses a URL or a response-string to doc tree'''
        #HACK. With CSW data need to check for JSON/masked 429s first
        try:
            if p=='fromstring': etp = self._parse_f(content)    #parse using string method
            else: etp = self._parse_p(content,p)                #parse normally or using provided parser
        except u_lib.HTTPError as he:
            raise #but this won't happen because LXML pushes HTTP errors up to IO errors
        except IOError as ioe:
            if re.search('failed to load HTTP resource', ioe.message):
                raise u_lib.HTTPError(content, 429, 'IOE. Possible HTTP429 Rate Limiting Error. '+ioe.message, None, None)
            raise u_lib.HTTPError(content, 404, 'IOE. Probable HTTP Error. '+ioe.message, None, None)
        except Exception as e:
            raise
        return etp
    
    def _parse_f(self,content):
        res = u_lib.urlopen(content).read()
        if re.search('API rate limit exceeded',res):
            raise u_lib.HTTPError(content, 429, 'Masked HTTP429 Rate Limiting Error. ', None, None)
        return etree.fromstring(res).getroottree()

    def _parse_p(self,content,p):
        return etree.parse(content,p) if p else etree.parse(content)

    def gettree(self):
        return self._tree
    
    def getroot(self):
        self.root = LXMLelem(self._tree,root=True)
        return self.root
    
    def get(self,path):
        self.elem = LXMLelem(self._tree,root=False,path=path)
        return self.elem
    
    def find(self,url,namespaces=None):
        return self._tree.find(url,namespaces) if sys.version_info[1]>6 else self._tree.find(LXMLetree._subNS(url, namespaces))
    
    def findall(self,url,namespaces=None): 
        reclist = self._tree.findall(url,namespaces) if sys.version_info[1]>6 else self._tree.findall(LXMLetree._subNS(url, namespaces))
        return [LXMLelem(e,wrap=True) for e in reclist]
    
class LXMLelem(object):
    '''Wrapper for the LXML element object, hacked to also act as a self wrapper for list/findall queries'''
    def __init__(self,parent,wrap=False,root=False,path=''):
        if wrap:
            self._elem = parent
        elif root: 
            self._elem = parent.getroot()
        elif path:
            #this isn't used (in current code) so hasn't been tested
            self._elem = parent.get(path)
        else:
            raise LXMLWrapperException('Missing Element descriptor')
        self.tag = self._elem.tag
        self.text = self._elem.text
        
    def get(self,path):
        return self._elem.get(path)    
    
    def items(self):
        return list(self._elem.items())
    
    def find(self,url,namespaces=None):
        '''returns element'''
        return self._elem.find(url,namespaces) if sys.version_info[1]>6 else self._elem.find(LXMLetree._subNS(url, namespaces))
    
    def findall(self,url,namespaces=None):
        reclist = self._elem.findall(url,namespaces) if sys.version_info[1]>6 else self._elem.findall(LXMLetree._subNS(url, namespaces))
        return [LXMLelem(e,wrap=True) for e in reclist]    
    

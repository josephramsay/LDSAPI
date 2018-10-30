'''
Created on 14/05/2015

@author: jramsay
'''
import os
import re
import urllib2 as U2
import socket
import base64
import time

from contextlib import closing
from lxml import etree
from lxml.etree import XMLSyntaxError, XMLSchemaParseError

try:
    from LDSLXML import LXMLetree, LXMLtree, LXMLelem
except ImportError:
    from LXMLWrapper.LDSLXML import LXMLetree, LXMLtree, LXMLelem
    

KEY = None
KEYINDEX = 0
#p1 = 'gmd:MD_Metadata/gmd:identificationInfo/gmd:MD_DataIdentification/'
p0 = 'gmd:MD_Metadata/'
p1 = 'gmd:identificationInfo/gmd:MD_DataIdentification/'
p2 = 'gmd:CI_Citation/gmd:date/gmd:CI_Date/'
p3 = 'gmd:descriptiveKeywords/gmd:MD_Keywords/gmd:thesaurusName/'
p4 = 'gmd:date/gco:Date'
p5 = 'gmd:dateType/gmd:CI_DateTypeCode'
#mxp = OrderedDict()#not available in 2.6
mxp = {}
#used for CSW validation [root = csw:GetRecordByIdResponse]
mxp.update({'ttl':p0+p1+'gmd:citation/gmd:CI_Citation/gmd:title/gco:CharacterString'})
mxp.update({'fid':p0+'gmd:fileIdentifier/gco:CharacterString'})
mxp.update({'abs':p0+p1+'gmd:abstract/gco:CharacterString'})
mxp.update({'tpc':p0+p1+'gmd:topicCategory/gmd:MD_TopicCategoryCode'})
mxp.update({'ath':p0+'gmd:contact/gmd:CI_ResponsibleParty/gmd:individualName/gco:CharacterString'})
mxp.update({'bba':p0+p1+'gmd:extent/gmd:EX_Extent/gmd:geographicElement/gmd:EX_GeographicBoundingBox/gmd:{compass}/gco:Decimal'})
mxp.update({'bbb':p0+p1+'gmd:extent/gmd:EX_Extent/gmd:geographicElement/gmd:EX_GeographicDescription'})
mxp.update({'ccl':p0+p1+'gmd:resourceConstraints/gmd:MD_LegalConstraints/gmd:useLimitation/gco:CharacterString'})
mxp.update({'pbd':p0+p1+'gmd:resourceConstraints/gmd:MD_LegalConstraints/gmd:useLimitation/gco:CharacterString'})
#used for metadata validation
mxp.update({'ttl2':p1+'gmd:citation/gmd:CI_Citation/gmd:title'})
mxp.update({'fid2':'gmd:fileIdentifier'})
mxp.update({'abs2':p1+'gmd:abstract'})
mxp.update({'tpc2':p1+'gmd:topicCategory/gmd:MD_TopicCategoryCode'})
mxp.update({'poc2':p1+'gmd:pointOfContact'})
mxp.update({'mds2':'gmd:dateStamp'})
mxp.update({'rfd2':p1+'gmd:citation/gmd:CI_Citation/gmd:date'})
mxp.update({'lng2':p1+'gmd:language'})
#lds xml metadate dates [root = gmd:MD_Metadata]
mxp.update({'fd':'gmd:dateStamp/gco:Date'})
mxp.update({'pd':p1+'gmd:citation/'+p2+p4})
mxp.update({'pdt':p1+'gmd:citation/'+p2+p5})
mxp.update({'rd':p1+p3+p2+p4})
mxp.update({'rdt':p1+p3+p2+p5})
mxp.update({'ed':p1+p3+'gmd:CI_Citation/gmd:editionDate/gco:Date'})



CRIT = False
MASK = True
MAX_DVL_RETRY = 3       #times
MAX_WFS_RETRY = 3       #times
MAX_WMS_RETRY = 3       #times
MAX_CSW_RETRY = 3       #times
LOL_LAST_UPDATE = 14    #days
SLEEP_TIME = 5*60       #secs
NAP_TIME = 10           #secs
URL_TIMEOUT = 3*60      #secs
CSW_INCR = 250          #records
CREDS = {}
WGRP = 'AD'
dvl_file = 'dvl.crs.gz'
dvl_table = 'bde.crs_title'
KEY_FILE = '.apikey1'

#Versions
CSW = '2.0.2'
WFS = '2.0.0'
WMS = '1.1.1'
GML = '3.2'
NSX = {'xlink'   : 'http://www.w3.org/1999/xlink',
       'xsi'     : 'http://www.w3.org/2001/XMLSchema-instance',  
       'dc'      : 'http://purl.org/dc/elements/1.1/',
       'g'       : 'http://data.linz.govt.nz/ns/g', 
       'r'       : 'http://data.linz.govt.nz/ns/r', 
       'ows'     : 'http://www.opengis.net/ows/1.1', 
       'csw'     : 'http://www.opengis.net/cat/csw/2.0.2',
       'wms'     : 'http://www.opengis.net/wms',
       'ogc'     : 'http://www.opengis.net/ogc',
       'gco'     : 'http://www.isotc211.org/2005/gco',
       'gmd'     : 'http://www.isotc211.org/2005/gmd',
       'gmx'     : 'http://www.isotc211.org/2005/gmx',
       'gsr'     : 'http://www.isotc211.org/2005/gsr',
       'gss'     : 'http://www.isotc211.org/2005/gss',
       'gts'     : 'http://www.isotc211.org/2005/gts',
       'f'       : 'http://www.w3.org/2005/Atom',
       'null'    : '',
       'wfs'     : 'http://www.opengis.net/wfs/2.0',
       'gml'     : 'http://www.opengis.net/gml/3.2',
       'v'       : 'http://wfs.data.linz.govt.nz',
       'lnz'     : 'http://data.linz.govt.nz'}



ANZLIC = os.path.abspath(os.path.join(os.path.dirname(__file__),'anzlic','gmd/gmd.xsd'))
    
class WebServiceException(Exception): pass
class WFSException(WebServiceException): pass
class WFSServiceException(WFSException): pass

class UPDException(Exception): pass
#class CategoriesUnavailableException(UPDException): pass
#class DateInconsistencyException(UPDException): pass
class DateAvailabilityException(UPDException): pass

class LDSMeta(object):
    '''
    Interface to metedata pages
    '''    
    
    mta = 'https://data.linz.govt.nz/layer/{lid}/metadata/iso/xml/'
    eplusm = (('div\sclass="loginSignin"','Inaccessible Private Layer [login]'),
              ('code="LayerNotDefined"','Layer Not Defined'),
              ('AxisDirection','AxisDirection (geotools) Bug'),
              ('IllegalArgumentException:\sAngle\s[0-9,.]*\sis\stoo\shigh','Angle-Too-High (geotools) Bug'),
              ('MismatchedReferenceSystemException:\sThe\scoordinate\sreference\ssystem\smust\sbe\sthe\ssame\sfor\sall\sobjects','Mismatched-SRS (geotools) Bug'),
              ('Unable\sto\screate\sthis\smosaic','Mosaic-Creation (geotools) Bug'),
              ('Failed\sto\smosaic\sthe\sinput\scoverages','Mosaic-Coverage (geotools) Bug'),
              ('java.io.IOException:\sFailed\sto\screate\sreader\sfrom\sfile','FileReader Error'))

    def __init__(self,upd,checklog):
        self.userpass = upd
        self.checklog = checklog
        self.tree = LXMLetree().parse(self.rs3.format(id=id[0].text,csw_v=CSW,gmd=NSX['gmd']))
        self.schema = self.schema()
###-------------------------------------------------------------------------------------------------------
# just want a class that you can pass a url to and it will retrn metadata object

###-------------------------------------------------------------------------------------------------------

    def metamandatory(self,tree):
        #here we check for the existence (only) of ANZLIC specific inclusuions, which may be optional as part of their schema type 
        #but required by anzlic nonetheless
        
        for xid in [x for i,x in enumerate(mxp) if re.search('\D+2$',x)]:#'gmd:MD_Meta',mxp[x])]:
            try:
                #NB have to use "is None" because ... lxml
                if tree.find(mxp[xid],namespaces=NSX) is None:#NB have added getroot since addng prefix md_metadata in mxp
                    raise WFSServiceException('Mandatory ANZLIC field {0} missing.'.format(mxp[xid]))
            except Exception as ee:
                raise WFSServiceException('Error reading ANZLIC field {0}. {1}'.format(mxp[xid],ee))
        return True
    
    def schema(self):
        '''Return a schema to validate against, anzlic/gmd'''
        schema = None
        try:
            with open(ANZLIC) as scontent:
                sdoc = LXMLetree().parse(scontent).gettree()
                schema = LXMLetree().XMLSchema(sdoc)
        except XMLSchemaParseError as xse:            
            print('WFSMeta XMLSchemaParseError causing Failure - {0}\nThis usually indicates a libxml2<2.7.8 problem'.format(xse))
            self.checklog.error('WFSxs - {0}'.format(xse))
        
        return schema
        
    def content(self,lid, content, url):
        '''Commonly occuring errors tested (WMS Comp, WFS meta)'''
        for ix,epm in enumerate(self.eplusm):
            if re.search(epm[0],content):
                #checklog.debug('WxS{0} {1} - Layer{2}, ANZLIC NOT checked.\n{3}'.format(i,epm[1],lid,kmask(url)))
                self.checklog.debug('WxS{0} {1} - Layer{2}, ANZLIC NOT checked'.format(ix,epm[1],lid))
                return '{0} - L{1}'.format(epm[1],lid)
        return None

    def getLDSURL(self,lid):
        return self.mta.format(lid=lid)
    
    def getCSWURL(self,fid):
        pass

    def metadata(self,lid):
        
        b64s = base64.encodestring('{0}:{1}'.format(*self.userpass)).replace('\n', '')

        svr = None
        url = self.mta.format(lid=lid)
        self.checklog.debug('WFS0u-'+kmask(url))

        retry = True
        while retry:
            retry = False
            content = None
            try:
                #cookiesetup(url)
                req = U2.Request(url)
                req.add_header('Authorization', 'Basic {0}'.format(b64s))   
                with closing(U2.urlopen(url=req, timeout=URL_TIMEOUT)) as content:
                    ct = str(content.read())
                    if self.content(lid, ct):#the checkcontent here pagesscrapes for valid XML without known errors so the parser wont break
                        continue
                    xdoc = LXMLetree().fromstring(ct)
                    #print xdoc.getroot().find('gmd:MD_Metadata',namespaces=NSX)
                    if self.schema.validate(xdoc.gettree()) and self.metamandatory(xdoc):
                    #if self.validate(content,schema):
                        self.checklog.debug('WFS0v-{0}'.format(lid))
                    else:
                        raise WFSServiceException('XML Fails validation against gmd.xsd with {0}'.format(self.schema.error_log.last_error.message))
            except U2.HTTPError as he:
                if re.search('429',str(he)):
                    self.checklog.debug('WFS0k - Swap keys and Retry on 429. {1}'.format(SLEEP_TIME,he))
                    global KEY
                    KEY = apikey(KEY_FILE)
                    if KEYINDEX == 0:
                        self.checklog.debug('WFS04 - Wait {0}s and Retry on 429. {1}'.format(SLEEP_TIME,he))
                        time.sleep(SLEEP_TIME)
                    retry = True
                    continue
                print('WFSMeta {0} Failure - {1}'.format(lid,he))
                self.checklog.error('WFSm0h - {0}/{1}\n{2} on server {3}'.format(lid,he,kmask(url),svr))
            except WFSServiceException as we:
                print('WFSMeta {0} XSD Failure - {1}'.format(lid,we))
                self.checklog.error('WFSm0se - {0}/{1}\n{2} on server {3}'.format(lid,we,kmask(url),svr))
            except XMLSyntaxError as xe:
                print('WFSMeta {0} XMLSyntaxError causing Parse Failure - {1}'.format(lid,xe))
                self.checklog.error('WFSm0x - {0}/{1}\n{2}\n{3} on server {4}'.format(lid,xe,kmask(url),ct[:100],svr))
            except U2.URLError as ue:
                print('WFS0ue {0} URLError - {1}'.format(lid,ue))
                if isinstance(ue.reason, socket.timeout):
                    self.checklog.error('WFS0uet - {0}/{1}\n{2} on server {3}. Retry'.format(lid,ue,kmask(url),svr))
                    retry = True
                    continue
                else:
                    self.checklog.error('WFS0ueo - {0}/{1}\n{2} on server {3}'.format(lid,ue,kmask(url),svr))
            except Exception as ee:
                print('WFS0ee {0} Exception - {1}'.format(lid,ee))
                self.checklog.error('WFS0ee - {0}/{1}\n{2} on server {3}'.format(lid,ee,kmask(url),svr))
                    

    
    
    def parse(self,pno):
        '''Parses useful date fields from LDS layer metadata XML'''
        retry = True
        ecounter = 0
        n1,n2,n3,n4 = 4*(0,)
        er = None
        url = 'https://data.linz.govt.nz/layer/{0}/metadata/iso/xml'.format(pno)
        dd = {}
        while retry:
            retry = False
            content = None
            try:
                #tree = LXMLetree().parse(url)
                with closing(U2.urlopen(url)) as content:
                    tree = LXMLetree().parse(content)

                    n1 = tree.getroot().find(mxp['fd'],namespaces=NSX).text
                    n2 = tree.getroot().find(mxp['pd'],namespaces=NSX).text
                    if n2 and not(re.search(tree.getroot().find(mxp['pdt'],namespaces=NSX),'publication')): raise DateAvailabilityException('Cannot associate date to datetype Pub')
                    n3 = tree.getroot().find(mxp['rd'],namespaces=NSX).text
                    if n3 and not(re.search(tree.getroot().find(mxp['rdt'],namespaces=NSX),'revision')): raise DateAvailabilityException('Cannot associate date to datetype Rev')
                    n4 = tree.getroot().find(mxp['ed'],namespaces=NSX).text
                
               
            except U2.HTTPError as he:
                if ecounter>MAX_DVL_RETRY:
                    raise
                else:
                    self.checklog.warn('LPS1 - Error parsing metadata dates '+pno)
                    ecounter += 1
                    retry = True
            except DateAvailabilityException as dae:
                self.checklog.warn('LPS2 - Error identifying date {0}. {1}'.format(pno,dae))
            finally:
                if content: content.close()
        return n1,n2,n3,n4,er
    
def kmask(ktext):
    '''Given a ktext string (eg url) mask out KEY'''
    return re.sub(KEY,'<api-key>',str(ktext))

def apikey(kfile):
    global KEYINDEX
    key = searchfile(kfile,'key{0}'.format(KEYINDEX))
    if not key:
        KEYINDEX = 0
        key = searchfile(kfile,'key{0}'.format(KEYINDEX))
    else:
        KEYINDEX += 1
    return key

def searchfile(sfile,skey,default=None):
    value = default
    with open(sfile,'r') as h:
        for line in h.readlines():
            k = re.search('^{key}=(.*)$'.format(key=skey),line)
            if k: value=k.group(1)
    return value


def test():
    ldsm = LDSMeta()
    ldsm.metadata(772)
    
if __name__ == '__main__':
    test()
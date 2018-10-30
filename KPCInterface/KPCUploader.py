'''
Created on 17/12/2015

@author: jramsay
'''

import pickle
import re
import os
import sys
import difflib
import time

from lxml import etree
from collections import namedtuple
from contextlib import closing
from functools import wraps, partial

#THISF = os.path.normpath(os.path.dirname(__file__))
#sys.path.append(os.path.abspath(os.path.join(THISF,'../../../python-client')))

import koordinates
from koordinates.exceptions import ServerError
from koordinates.layers import LayerData

#from APIInterface.LDSAPI2 import DataAccess

if os.name=='posix':
    DIRECT_COPY = False
    import smbc
else:
    DIRECT_COPY = True
    
from KPCInterface.KPCAPI import LayerInfo, LayerRef
from KPCInterface.KPCAPI import LDS_TEST,LDS_LIVE
from KPCInterface.AuthReader import Authentication,ConfigAuthentication

p0 = 'gmd:MD_Metadata/' #don't use since first element is root and not found in xpath/find espr
p1 = 'gmd:identificationInfo/gmd:MD_DataIdentification/'

NS = {'xlink'   : 'http://www.w3.org/1999/xlink',
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

#groups added manually from https://data-test.linz.govt.nz/services/api/v1/groups/
DEFINITIONS = {'electoral':{'smb_server':'bde_server','smb_path':'data,bde',
                      'source_id':33,'datasource_id':0,'group_id':101},
               'topo':{'smb_server':'lds_data_staging','smb_path':'data,topo,LDS_Topo_SHAPE,NZ-Mainland-Topo50',
                       'source_id':603,'datasource_id':193789,'group_id':103},
               'hydro':{'smb_server':'lds_data_staging','smb_path':'data,hydro',
                        'source_id':622,'datasource_id':0,'group_id':102},
               '<test>':{'smb_server':'localhost','smb_path':'data,test',
                        'source_id':0,'datasource_id':0,'group_id':0}
               }

SHP_SUFFIXES = ('cpg','dbf','xml','prj','shp','shx')

LOGGER = None
CONFIG = None
UICONFIG = None

CREDS = {}
KEY = ''
EXACT = True
OVERWRITE = False
WAIT_INTERVAL = 5
MATCH_THRESHOLD = 1


class LayerMatchException(Exception): pass
     
            
class LDSPushController(object):
    '''Controls matching between LDS and layer-upload-request'''
    
    DEF_DB_PARAMS = {'host':'127.0.0.1','port':5432,'user':'postgres','pass':None,'database':'postgres','schema':None,'table':None}
    DEF_FILE_PATH = '~/shapefile.shp'

    def __init__(self,client,ul=False):
        self.client = client
        self.lr = LayerRef(self.client,ul)
        self.connector = Connector if DIRECT_COPY else SMBConnector
        
    def fileinfo(self,fg):
        '''extracts data fields from layer file xml'''
        res = {'title':[p1+'gmd:citation/gmd:CI_Citation/gmd:title/gco:CharacterString',None],
               'published':[p1+'gmd:resourceConstraints/gmd:MD_LegalConstraints/gmd:useLimitation/gco:CharacterString',None]
               }

        with open('{}.xml'.format(fg)) as content:
            ct = str(content.read())
            xdoc = etree.fromstring(ct)
            for k in res: 
                res[k][1] = xdoc.find(res[k][0],namespaces=NS).text
    
        return res                                           
                               
    def filepush(self,fgroup):#,ftype):#fid,fname,ftype):
        #success = True
        missing = None
        fgroup = os.path.expanduser(fgroup)
        self.connection = self.connector(DEFINITIONS[self.user_group]['smb_server'],DEFINITIONS[self.user_group]['smb_path'])
        
        localpath = os.path.dirname(fgroup)
        localbase = os.path.basename(fgroup)
        available = ['{}.{}'.format(fgroup,p) for p in SHP_SUFFIXES if os.path.exists('{}.{}'.format(fgroup,p))]
        unavailable = ['{}.{}'.format(fgroup,p) for p in SHP_SUFFIXES if '{}.{}'.format(fgroup,p) not in available]

        #make sure the latest xml for the layer is available
        if unavailable:
            #if some files are missing locally but seldom change, get them off the server eg xml metadata
            for f in unavailable:
                if f[f.rfind('.'):] in ('.xml','.prj','.cpg'):
                    f = self.connection.fetch(f)
                    if f: 
                        available.append(f)
                        unavailable.remove(f)
            
        #then query the xml for the layer name
        res = self.fileinfo(fgroup)
        title = res['title'][1]
        #searches for an exact match +/- Mainland keyword OR uses a difflib close match
        ###lref = [l for l in self.lr.layeridmap if self._textMatch(title,l)] if EXACT else difflib.get_close_matches(title,self.lr.layeridmap,cutoff=0.8,n=1)[0]
        lref = self._listMatch(title,self.lr.layeridmap, MATCH_THRESHOLD)
        LOGGER.emit('Matched SHP title "{}" with LDS layer name "{}" - t={}'.format(title,lref[0],MATCH_THRESHOLD))
        if not lref:
            return self.createLayer(LayerInfo(title=title,id=None,version=None,versions=[],dates=None, files=available))
            #raise LayerMatchException('Cannot match layer name {}'.format(title))
        else:
            return self.updateLayer(self.lr.layeridmap[lref[0]]._replace(files = available))
            


    def _publishExistingDraft(self,layer,vers):
        '''just used to test promoting draft layers to published'''
        self.publishDraft(vers['draft'].values()[0])
            
    def _removeOtherVersions(self,layer,vers):
        for ver in vers['other']: layer.delete_version(ver)
        
    def _listMatch(self,title,titlelist,threshold=1):
        if threshold==1:
            #do a crappy difflib match (most likely to have errors)
            return difflib.get_close_matches(title,titlelist,cutoff=0.8,n=1)
        else:
            return [l for l in self.lr.layeridmap if self._textMatch(title,l,threshold)]
            
    def _textMatch(self,t1,t2,threshold=1):
        '''rules for matching layer names'''
        assert threshold==0, 'threshold set to 0'
        if t1==t2: return True #exact match is exact match
        elif (t1==t2.replace('Mainland ','') or t2==t1.replace('Mainland ','')) and 2>threshold: return True
        return 1>threshold #assuming min(t)=0 everything matches!
        
        
        
    def newlayerexistingds(self):pass
    def newlayernewds(self):pass
    def existinglayerexistingds(self):pass
    def existinglayernewds(self):pass
    
    def dbpush(self,id,params=DEF_DB_PARAMS):
        if not params: params = self.DEF_DB_PARAMS
        
    def updateLayer(self,linfo):
        #[os.path.basename(path) for path in available+unavailable]
        #push the layer and notify LDS
        if self.connection.synchronise(linfo, update=True):
            layer = self.client.layers.get(linfo.id)
            LOGGER.emit('Update Layer {}'.format(linfo.id))
            new_draft,new_status = None,None
            vers = self._gerVer(layer)
            #self._publishExistingDraft(layer, vers)
            if not vers['draft'] or OVERWRITE:
                new_draft = self.createDraft(layer,linfo._replace(versions = vers['draft']))
                vers = self._gerVer(new_draft)
                new_status = self._getStatus(vers['draft'], wait=True)
            if new_draft and new_status=='ok' and (not vers['published'] or OVERWRITE): 
                return self.publishDraft(new_draft)
        
    def createLayer(self,linfo):
        '''create a new (draft) layer in an existng datasource'''
        new_draft,new_status = None,None
        self.connection.synchronise(linfo,update=False)
        #create new layer
        LOGGER.emit('Create Layer {}'.format(linfo.id))
        layer = koordinates.Layer()
        layer.title = linfo.title
        layer.group = DEFINITIONS[self.user_group]['group_id']  
        raise Exception('Cant create new layers without first adding a datasource')
        layer.data = LayerData(datasources=[DEFINITIONS[self.user_group]['datasource_id']])
        new_draft = self.client.layers.create(layer)
        LOGGER.emit('Import {}'.format(layer.id))
        new_draft.start_import()
        ####################
        vers = self._gerVer(new_draft)
        new_status = self._getStatus(vers['draft'], wait=True)
        if new_draft and new_status=='ok' and (not vers['published'] or OVERWRITE): 
            return self.publishDraft(new_draft)
    
    def createDraft(self,layer,linfo):
        '''create a new draft and sets its metadata'''
        md = [os.path.basename(f) for f in linfo.files if re.search('xml$',f)]
        dvers = list(linfo.versions.keys())
        LOGGER.emit('Create Draft {}'.format(layer.id)) 
        try:
            #either OW is set or draft is empty
            if dvers: layer.delete_version(dvers[0])
            new_draft = layer.create_draft_version()
            LOGGER.emit('Import {}'.format(layer.id))
            new_draft.start_import()
            #if md: new_draft.set_metadata(md[0])
            return new_draft
        except ServerError as se:
            print ('{}. Draft version {} already loaded'.format(se,layer))

        
    def publishDraft(self,layer):
        '''Once a draft has been created, publish''' 
        LOGGER.emit('Publish {}'.format(layer.id))
        try:
            publisher = layer.publish()
            return publisher
        except ServerError as se:
            print ('{}. Draft version {} already published'.format(se,layer))

        
    def _gerVer(self,layer):
        versions = {k:{} for k in ('draft','published','other')}
        try:
            for v in layer.list_versions():
                ver =  layer.get_version(v.id)
                if ver.is_draft_version: versions['draft'][v.id] = ver
                elif ver.is_published_version: versions['published'][v.id] = ver  
                else: versions['other'][v.id] = ver
        except Exception as e:
            print ('Error {} getting version for {}'.format(e,layer))

        return versions
    
    def _getStatus(self,dvers,wait=False):
        '''return version status and wait for it to be 'ok' if asked'''
        dvid = list(dvers.keys())[0]
        layer = list(dvers.values())[0]
        status = layer.version.status
        if wait:
            while status!='ok':
                time.sleep(WAIT_INTERVAL)
                dvers = self._gerVer(layer)['draft']
                status = list(dvers.values())[0].version.status
                progress = list(dvers.values())[0].version.progress*100
                LOGGER.emit('Layer {} {} at {}%'.format(dvid,status, progress))
        return status
    
class Connector(object):
    SMB_SERVER = 'bde_server'
    SMB_PATH = 'Bde_Data/level_5'    
    
    def __init__(self,shost=SMB_SERVER,spath=SMB_PATH): 
        self.host = shost
        self.path = os.path.sep.join(spath.split(','))   
        self.remotepath = '{sep}{sep}{host}{sep}{path}'.format(host=self.host,path=self.path,sep=os.path.sep)

    
    def _open(self,fname,mode):
        return open(fname,mode)
    
    def _listdir(self,dname):
        return os.listdir(dname)
    
    def fetch(self, lfn):
        '''fetch an indivdual remote file'''
        rfn = lfn[lfn.rfind(os.path.sep):]
        rfile = None
        LOGGER.emit('{} <- {}'.format(lfn,self.remotepath,rfn))
        try:
            with closing(self._open(self.remotepath+rfn)) as rfile:
                with closing(self._open(lfn, 'wb')) as lfile:
                    print (rfile,lfile)
                    lfile.write(rfile.read())
        except AttributeError as ae:
            raise
        except IOError as ioe:
            raise
        except Exception as nee:
            print ('TODO. isolate this missing file error:',nee)
            lfn = None

        finally:
            #because closing doesnt always work on smbc objects
            if rfile: rfile.close()
        return lfn
    
    def post(self, localfile):
        pass
    
    def synchronise(self,li, update=True):
        '''syncs files for a particular file-group between local and staging resources'''
        localfiles = [os.path.split(f) for f in li.files]
        remotefiles,matchingfiles = [],[]
        '''Get a directry listing'''#\\lds_data_staging\data\topo\LDS_Topo_SHAPE\NZ-Mainland-Topo50
        try:
            remotefiles = self._listdir(self.remotepath)
        except Exception as e:
            print ('Error getting remote files list.',e)
        #match remote to upload files to trigger update rather than create process. metadata file for a layer will often stay the same so can be skipped
        if update:
            matchingfiles = [d for d in remotefiles if re.match('|'.join([u[1] for u in localfiles]),d)] 
            if len(localfiles) != len(matchingfiles): raise Exception("Can't send non-matching file set")
        
        #TODO. match on timestamp to prevent unnecessary overwriting
        for f1 in localfiles:
            try:
                #open files being replaced
                
                lfn = '{0}{1}{2}'.format(f1[0],os.path.sep,f1[1])
                rfn = '{0}/{1}'.format(self.remotepath,f1[1])
                with closing(self._open(rfn,'wb')) as rfile:
                    #open files being uploaded
                    #ikiiki,mode,ino(L),dev(L),nlink(L),uid,gid,size(L),atime,mtime,ctime
                    rsize = rfile.fstat()[6]
                    lsize = os.stat(lfn).st_size
                    if rsize != lsize:
                        LOGGER.emit('Transferring {}({})->{}({})'.format(lfn,lsize,rfn,rsize))
                        with open(os.path.expanduser(lfn), 'rb') as lfile:
                            rfile.write(lfile.read())
                    else:
                        LOGGER.emit('Local and remote files are identical, skipping {}'.format(lfn))

            except AttributeError as ae:
                #Commonly occurs with older versions (<1.0.10) of smbc which has no file accessor functions. Attempt cmdline instead
                raise
                #checklog.warn('DVLsmb1 - Unable to open SMB file using pysmbc, {0}. Attempting CL access.'.format(ae))
                
            except IOError as ioe:
                raise
                #checklog.debug('DVLsmb2 - IO Error reading {0}. {1}'.format(DVL_FILE,ioe))
            except Exception as e:
                raise
            finally:
                #because closing doesnt always work on smbc objects
                rfile.close()

        return matchingfiles

class SMBContext():
    '''Wrapper class bracketting common function calls in context setup and teardown methods'''    
    @classmethod
    def ctxwrap(cls,func=None):
        if func is None:
            return partial(cls.ctxwrap)
        @wraps(func)
        def wrapper(*args, **kwargs):
            SMBConnector._setup()
            rv = func(*args, **kwargs)
            SMBConnector._teardown()
            return rv
        return wrapper
    
class SMBConnector(Connector):
    '''subclass of connector using pysmbc'''
    
    def __init__(self,shost,spath): 
        super(SMBConnector,self).__init__(shost, spath)
        self.remotepath = 'smb://{host}/{path}'.format(host=self.host,path=self.path)
        
    @classmethod
    def _setup(self):
        self.ctx = smbc.Context()
        #self.ctx.timeout = 100000
        self.ctx.optionNoAutoAnonymousLogin = True
        self.ctx.functionAuthData = _g_auth_cb_fn #setup user/pass/dom

    @classmethod
    def _teardown(self):
        del self.ctx
        
    def __enter__(self):
        self._setup()
        
    def __exit__(self):
        self._teardown()

    def _open(self,fname,mode):
        return self.ctx.open(fname,{'wb':os.O_CREAT | os.O_WRONLY,'rb':os.O_RDONLY}[mode])
        #if mode == 'rb':
        #    h = self.ctx.open(fname,os.O_RDONLY)
        #else:
        #    h = self.ctx.open(fname,os.O_CREAT | os.O_WRONLY)
        #return h
    
    def _listdir(self,dname):
        return [d.name for d in self.ctx.opendir(dname).getdents()]
    
    @SMBContext.ctxwrap
    def synchronise(self,li, update=True):
        return super(SMBConnector,self).synchronise(li,update)
            
    @SMBContext.ctxwrap
    def fetch(self,lfn):
        return super(SMBConnector,self).fetch(lfn)

    
class LDSUploader(object):
    '''file transfer and api controller'''
    
    def __init__(self,logger,ow=False,up=False):
        '''set up authentication and connectivity'''
        AA = ConfigAuthentication(CONFIG) if CONFIG else Authentication
        global LOGGER 
        LOGGER = logger
        global OVERWRITE
        OVERWRITE = next((el for el in [ow,UICONFIG.opt_overwrite,CONFIG.server_overwrite] if el is not None),None)
        global KEY
        KEY = AA.apikey()
        global CREDS
        CREDS['u'],CREDS['p'],CREDS['d'] = AA.creds()
        
        self.client = koordinates.Client(host=LDS_TEST, token=KEY)
        self.lpc = LDSPushController(self.client,up)
        
    def setLayer(self,fg):
        self.fgroup = fg#list(set([x[:x.rfind('.')] for x in TF616]))[0]
        
    def setGroup(self,ug):
        self.ugroup = ug
        
    def upload(self,layer=None):
        '''upload a single layer'''
        #assume we are given a name a path and a type, tunnel_cl, c:\users\myfiles\, topo
        #append path and name to get a path+base
        if layer: self.setLayer(layer)
        self.lpc.user_group = self.ugroup
        self.lpc.filepush(self.fgroup) #*self.testid)
        
    def redact(self):
        pass
    
class LDSUploaderWrapper(LDSUploader):
    '''Wrapper to pass alt config object args'''
    def __init__(self,logger,uiconfig,config):
        setConfig(uiconfig,config)
        super(LDSUploaderWrapper,self).__init__(logger,uiconfig.opt_overwrite,uiconfig.opt_update)
        self.setGroup(uiconfig.val_grp)
        
def setConfig(uiconfig,config):
    global CONFIG
    CONFIG = config
    global UICONFIG
    UICONFIG = uiconfig
    global DEFINITIONS
    DEFINITIONS = config.remote_defs

 
def _g_auth_cb_fn(server, share, workgroup, username, password):
    return (CREDS['d'].upper(),CREDS['u'],CREDS['p'])
 
def main():
    ldsup = LDSUploader()
    ldsup.upload()

            
if __name__ == '__main__':
    main()       
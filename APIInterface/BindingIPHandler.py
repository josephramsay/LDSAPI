'''
Created on 6/03/2015

@author: jramsay

Hack to set Source IP in HTTP header (to spoof web request sources and defeat 429 errors). 
Relies on server reading http header info for source IP so won't work with reply-to-sender schemas

'''
import urllib2, httplib, socket

IPADDR = '127.0.0.1'

class BindableWrapper(object):

    ipaddr = '127.0.0.1'
    
    def __init__(self):
        #self.ipaddr = socket.gethostbyname(socket.gethostname())
        self.ipaddr = self._local()
        
    def _local(self):
        return [(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
    
    def getLocalIP(self,reset=False):
        global IPADDR
        if reset:
            ipa = self._local()
        else: #increment
            lastdot = self.ipaddr.rfind('.')
            ipa = self.ipaddr[:lastdot]+'.'+str(int(self.ipaddr[lastdot+1:])%254+1)
            
        self.ipaddr = ipa
        IPADDR = ipa
        print ('setting ip to',ipa)
        return ipa
            
    @staticmethod        
    def BindableConnectionFactory(source_ip,https=False):
        def _get(host, port=None, strict=None, timeout=0):
            if https: bhc = BindableHTTPSConnection(host, port=port, strict=strict, timeout=timeout)
            else: bhc = BindableHTTPConnection(host, port=port, strict=strict, timeout=timeout)
            bhc.source_ip=source_ip
            return bhc
        return _get

class BindableHTTPConnection(httplib.HTTPConnection):
    def connect(self):
        """Connect to the host and port specified in __init__."""
        print ('binding http ip',self.source_ip)
        self.sock = socket.socket()
        self.sock.bind((self.source_ip, 0))
        if isinstance(self.timeout, float):
            self.sock.settimeout(self.timeout)
        self.sock.connect((self.host,self.port))
        
        
class BindableHTTPSConnection(httplib.HTTPSConnection):
    def connect(self):
        """Connect to the host and port specified in __init__."""
        print ('binding https ip',self.source_ip)
        self.sock = socket.socket()
        self.sock.bind((self.source_ip, 0))
        if isinstance(self.timeout, float):
            self.sock.settimeout(self.timeout)
        self.sock.connect((self.host,self.port))

class BindableHTTPHandler(urllib2.HTTPHandler):
    def http_open(self, req):
        return self.do_open(BindableWrapper.BindableConnectionFactory(IPADDR,False), req)
    
class BindableHTTPSHandler(urllib2.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(BindableWrapper.BindableConnectionFactory(IPADDR,True), req)

'''
Created on 17/12/2013

@author: jramsay
'''

#https://koordinates.com/services/api/v1/sources/1/

import unittest
import json
import os


from APIInterface.LDSAPI import SourceAPI
from .TestFileReader import FileReader
from .TestSuper import APITestCase

sources = (
    ("Alices' Mapinfo Server", "mapinfo", "No Proxy - No Auth", [], 3, "alice", "alicespassword", "https://alice.example.com/Mapinfo/rest/services", "@hourly"),
    ("Bob's ArcGIS 10 Server", "arcgis",  "Proxy (CNTLM) - No Auth", [], 3, "bob", "bobspassword", "https://bob.example.com/ArcGIS/rest/services", "@daily"),
    ("Carol's PostGIS 8 Server", "postgis",  "Proxy (Corp Web) - No Auth", [], 3, "carol", "carols password", "https://carol.example.com/PostGis/rest/services", "@weekly"),
    ("Dan's SpatiaLite 4 Server", "spatialite", "No Proxy - Auth (aio)", [], 3, "dan", "danspassword", "https://dan.example.com/SpatiaLite/rest/services", "@yearly"),
    ("Erin's Grass 12 server", "grass", "Proxy (CNTLM) - Auth (aio)", [], 3, "erin", "erinspassword", "https://erin.example.com/Grass/rest/services", "@quarterly"),
    ("Frank's FileGDB 2 Server", "filegdb", "Proxy (Corp Web) - Auth (aio)", [], 3, "frank", "frankspassword", "https://frank.example.com/FileGDB/rest/services", "@occasionally"),
    ("WORKING PG SERVER", "postgis", "Proxy (Corp Web) - Auth (aio)", [], 3, "pguser", "pgpass", "https://linz.govt.nz/PostGIS/rest/services", "@daily")
)


class SourcesTester(APITestCase):
    def setUp(self):
        print('S')
        self.api = SourceAPI(FileReader.creds,self.cdir+self.cfile)
        self.api.setParams()
        
    def tearDown(self):
        self.api = None
        

         
    def test_21_GetNoProxyAuth(self):
        self.api.connect()
        self.api.dispRes(self.api.res)


    def test_30_BasicJSONWrite(self):
        self.api.connect()
        be = json.dumps(self.api.res)
        pp = json.dumps(self.api.res, sort_keys=True, indent=4, separators=(',', ': '))
        
        print(be,pp)

    
if __name__ == '__main__':
    unittest.main()
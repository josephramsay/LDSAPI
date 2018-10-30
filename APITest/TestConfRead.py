'''
Created on 23/12/2013

@author: jramsay
'''

#https://koordinates.com/services/api/v1/sources/1/

import unittest
import json



from Main import CReader

        
class DataTester(unittest.TestCase):
    
    def setUp(self):
        self.cr = CReader('../APIInterface/sampledata')
        
    def tearDown(self):
        self.cr = None
        
    def test_10_ReadConfSecs(self):
        for s in self.cr.listSections():
            print('Sec',s)
            
    def test_20_ReadConfOpts(self):
        for s in self.cr.listSections():
            print('Sec',s,'Opt',self.cr.readHDSection(s))



    
if __name__ == '__main__':
    unittest.main()
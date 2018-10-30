'''
v.0.0.9

DSAPITester - LDSAPITestSuiteRunner

Copyright 2011 Crown copyright (c)
Land Information New Zealand and the New Zealand Government.
All rights reserved

This program is released under the terms of the new BSD license. See the 
LICENSE file for more information.

Test Suite runner

Created on 23/12/2013

@author: jramsay
'''
import unittest

#from APITest.LDSAPI import LDSAPI as T1

from APITest.TestDataAPI import DataTester as T2
#from APITest.TestSourceAPI import SourcesTester as T3
#from APITest.TestRedactionAPI import RedactionTester as T4



class LDSAPITestSuite(unittest.TestSuite):

    def __init__(self):
        pass
    
    def suite(self):
        suites = ()
        #suites += unittest.makeSuite(T1)
        suites += unittest.makeSuite(T2, 'test')    #data
        #suites += unittest.makeSuite(T3)            #redact
        #suites += unittest.makeSuite(T4)            #source

        
        return unittest.TestSuite(suites)

    
def main():
    
    suite  = LDSAPITestSuite()
    
    runner = unittest.TextTestRunner()
    runner.run(suite)
    
if __name__ == "__main__":
    main()

    
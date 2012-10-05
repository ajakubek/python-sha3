#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gc
import sys
import unittest

gc.set_debug(gc.DEBUG_UNCOLLECTABLE | gc.DEBUG_STATS)

if sys.hexversion >= 0x03000000:
    test_names = [
        'py3_tests.test_sha_224',
        'py3_tests.test_sha_256',
        'py3_tests.test_sha_384',
        'py3_tests.test_sha_512',
    ]
else:
    test_names = [
        'py2_tests.test_sha_224',
        'py2_tests.test_sha_256',
        'py2_tests.test_sha_384',
        'py2_tests.test_sha_512',
    ]

def suite():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    suite.addTest(loader.loadTestsFromNames(test_names))
    return suite


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())

#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import validation
from validation import TestConnectAutoconnect
from iwd import IWD

class Test8021xNetwork(unittest.TestCase):
    '''
    The bellow test cases excesise the following connection scenarios:

    Network config is
    present at start time:  Connect:  Autoconnect:  Result:
    --------------------------------------------------------------------------
    False                             True          NotConfiguredEx is thrown
    True                              True          Connection succeeds
    True - EAP method in    True                    NotSupportedEx is thrown
       config file is not
       supported by IWD
    '''
    def test_8021x(self):
        tca = TestConnectAutoconnect()
        tca.validate('ssidEAP-TLS', True, iwd.NotConfiguredEx)

        IWD.copy_to_storage('ssidEAP-TLS.8021x')

        tca.validate('ssidEAP-TLS', True)

        IWD.clear_storage()
        IWD.copy_to_storage('ssidEAP-Other.8021x')

        tca.validate('ssidEAP-Other', False, iwd.NotSupportedEx)

        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

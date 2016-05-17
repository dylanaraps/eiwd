#!/usr/bin/python3

#built-in python libraries
import unittest
import dbus
import logging
import sys
sys.path.append('../utility') #needed to import all the utility modules
import utility

# start this test without hostapd
class TestScanNetworkWithoutAP(unittest.TestCase):

    def test_scanNetworkWithoutAP(self):
        logger.info(sys._getframe().f_code.co_name)
        # scan and get network name
        deviceList = utility.getDeviceList(bus)
        networkList = utility.getNetworkList(deviceList, bus)
        networkName = utility.getNetworkName(networkList)
        logger.info("Network Found: %s", networkName)
        # should not find any network since hostapd is not running.
        self.assertEqual(networkName, "")

    @classmethod
    def setUpClass(cls):
        global logger, bus
        utility.initLogger()
        logger = logging.getLogger(__name__)
        bus = dbus.SystemBus()

if __name__ == '__main__':
    unittest.main(exit=True)

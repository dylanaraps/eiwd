#!/usr/bin/python3

#built-in python libraries
import unittest
import dbus
import logging
import sys
import time
import os
sys.path.append('../utility') #needed to import all the utility modules
import utility

class TestScanNetwork(unittest.TestCase):
    def test_scanNetwork(self):
        logger.info(sys._getframe().f_code.co_name)
        deviceList = utility.getDeviceList(bus)
        networkList = utility.getNetworkList(deviceList, bus)
        networkName = utility.getNetworkName(networkList)
        # check if networkName is not null. If yes, restart program.
        # Alternatively, we can scan for networks.
        if networkName == "":
            time.sleep(2)
            logger.debug("RESTART PROGRAM")
            os.execl(sys.executable, sys.executable, * sys.argv)

        logger.info("Network Found: %s", networkName)
        self.assertEqual(networkName, "IntelWIFI")

    @classmethod
    def setUpClass(cls):
        global logger, bus
        utility.initLogger()
        logger = logging.getLogger(__name__)
        bus = dbus.SystemBus()

if __name__ == '__main__':
    unittest.main(exit=True)

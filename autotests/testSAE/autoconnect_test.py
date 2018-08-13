#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = IWD(True)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()

        network = [x for x in ordered_networks if x.name == "ssidSAE"][0]

        self.assertIsNotNone(network)
        self.assertEqual(network.name, "ssidSAE")
        self.assertEqual(network.type, NetworkType.psk)

        condition = 'obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        device.wait_for_connected()

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        del wd

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidSAE.psk')
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

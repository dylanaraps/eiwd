#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD

class Test(unittest.TestCase):

    def connect_to_new_network(self, wd):
        devices = wd.list_devices(1);
        self.assertIsNotNone(devices)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()
        ordered_network = ordered_networks[0]

        self.assertEqual(ordered_network.name, "ssidNew")

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def list_removal_and_addition(self, wd):

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 3)

        wd.forget_known_network(known_networks[0])

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 2)

        self.connect_to_new_network(wd)

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 3)

        for net in known_networks:
            wd.forget_known_network(net)

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 0)

    def test_known_networks(self):
        wd = IWD(True)

        try:
            self.list_removal_and_addition(wd)
        except:
            del wd
            raise

        del wd

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('known_networks/ssidOpen.open')
        IWD.copy_to_storage('known_networks/ssidTKIP.psk')
        IWD.copy_to_storage('known_networks/ssidEAP-TLS.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = IWD(True, '/tmp/IWD-Frag')
        wd.wait(1)

        devices = wd.list_devices();
        self.assertIsNotNone(devices)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()
        ordered_network = None

        for o_n in ordered_networks:
            if o_n.name == "ssidEAP-PWD-frag":
                ordered_network = o_n
                break

        self.assertEqual(ordered_network.name, "ssidEAP-PWD-frag")
        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        try:
                ordered_network.network_object.connect()
        except:
                raise

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        del wd

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-PWD-frag.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

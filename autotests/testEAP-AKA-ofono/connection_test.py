#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
from hlrauc import AuthCenter
from ofono import Ofono

class Test(unittest.TestCase):

    def test_connection_success(self):
        auth = AuthCenter('/tmp/hlrauc.sock', '/tmp/sim.db')

        ofono = Ofono()
        ofono.enable_modem('/phonesim')
        ofono.wait_for_sim_auth()

        wd = IWD()

        devices = wd.list_devices(1);
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()
        ordered_network = ordered_networks[0]

        self.assertEqual(ordered_network.name, "ssidEAP-AKA")
        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        try:
                ordered_network.network_object.connect()
        except:
                auth.stop()
                raise

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        auth.stop()
    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-AKA.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
from hlrauc import AuthCenter

from hostapd import HostapdCLI
from hostapd import hostapd_map

class Test(unittest.TestCase):

    def test_connection_success(self):
        hostapd = None

        for hostapd_if in list(hostapd_map.values()):
            hpd = HostapdCLI(hostapd_if)
            if hpd.get_config_value('ssid') == 'ssidEAP-SIM':
                hostapd = hpd
                break

        auth = AuthCenter('/tmp/hlrauc.sock', '/tmp/sim.db')

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

        self.assertEqual(ordered_network.name, "ssidEAP-SIM")
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

        hostapd.eapol_reauth(device.address)

        wd.wait(10)

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        auth.stop()

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-SIM.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

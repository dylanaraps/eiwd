#!/usr/bin/python3

import unittest
import sys
import time

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
import testutil

from hostapd import HostapdCLI
from hostapd import hostapd_map

class Test(unittest.TestCase):

    def validate_connection(self, wd):
        hostapd = None

        for hostapd_if in list(hostapd_map.values()):
            hpd = HostapdCLI(hostapd_if)
            if hpd.get_config_value('ssid') == 'ssidEAP-PEAPv0-NoISK':
                hostapd = hpd
                break

        self.assertIsNotNone(hostapd)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('ssidEAP-PEAPv0-NoISK')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        hostapd.eapol_reauth(device.address)

        wd.wait(10)

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)


    def test_connection_success(self):
        wd = IWD(True)

        self.validate_connection(wd)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-PEAPv0-NoISK.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

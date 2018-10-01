#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import testutil
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

from hostapd import HostapdCLI
from hostapd import hostapd_map

class Test(unittest.TestCase):

    def test_connection_success(self):
        hostapd = None

        for hostapd_if in list(hostapd_map.values()):
            hpd = HostapdCLI(hostapd_if)
            if hpd.get_config_value('ssid') == 'ssidEAP-TTLS-PAP':
                hostapd = hpd
                break

        self.assertIsNotNone(hostapd)

        wd = IWD()

        psk_agent = PSKAgent('abc', ('user', 'testpasswd'))
        wd.register_psk_agent(psk_agent)

        device = wd.list_devices(1)[0];

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()
        ordered_network = ordered_networks[0]

        self.assertEqual(ordered_network.name, "ssidEAP-TTLS-PAP")
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

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-TTLS-PAP.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

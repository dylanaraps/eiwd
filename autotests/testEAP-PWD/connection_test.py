#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

from hostapd import HostapdCLI
from hostapd import hostapd_map

class Test(unittest.TestCase):

    def validate_connection(self, wd):

        hostapd = None

        for hostapd_if in list(hostapd_map.values()):
            hpd = HostapdCLI(hostapd_if)
            if hpd.get_config_value('ssid') == 'ssidEAP-PWD':
                hostapd = hpd
                break

        self.assertIsNotNone(hostapd)

        psk_agent = PSKAgent('eap-pwd-identity', ('eap-pwd-identity',
                                                                  'secret123'))
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1);
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
            if o_n.name == "ssidEAP-PWD":
                ordered_network = o_n
                break

        self.assertEqual(ordered_network.name, "ssidEAP-PWD")
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

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_connection_success(self):
        wd = IWD(True)

        try:
            self.validate_connection(wd)
        except:
            del wd
            raise

        del wd

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-PWD.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

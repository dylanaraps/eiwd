#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
import testutil
import hostapd

class Test(unittest.TestCase):

    def do_test_connection_success(self, ssid, passphrase=None):
        wd = IWD()

        if passphrase:
            psk_agent = PSKAgent(passphrase)
            wd.register_psk_agent(psk_agent)

        hostapd_ifname = None
        for ifname in hostapd.hostapd_map:
            if ssid + '.conf' in hostapd.hostapd_map[ifname].config:
                hostapd_ifname = ifname
                break

        devices = wd.list_devices(1);
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        if not device.get_ordered_networks():
            device.scan()
            condition = 'obj.scanning'
            wd.wait_for_object_condition(device, condition)
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()
        ordered_network = [n for n in ordered_networks if n.name == ssid][0]

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(hostapd_ifname, 'wln3')

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        if passphrase:
            wd.unregister_psk_agent(psk_agent)

    def test_eap_tls(self):
        self.do_test_connection_success('ssidEAP-TLS')

    def test_eap_tls2(self):
        self.do_test_connection_success('ssidEAP-TLS2')

    def test_eap_tls3(self):
        self.do_test_connection_success('ssidEAP-TLS3', 'abc')

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-TLS.8021x')
        IWD.copy_to_storage('ssidEAP-TLS2.8021x')
        IWD.copy_to_storage('ssidEAP-TLS3.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

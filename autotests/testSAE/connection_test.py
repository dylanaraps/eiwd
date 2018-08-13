#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import hostapd_map
import testutil

class Test(unittest.TestCase):

    def test_connection_success(self):
        hostapd_if = None

        for hostapd in list(hostapd_map.values()):
            if hostapd.config == 'ssidSAE.conf':
                hostapd_if = hostapd.name

        wd = IWD(True)

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

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

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        wd.wait(2)

        testutil.test_iface_operstate(intf=device.name)
        testutil.test_ifaces_connected(if0=device.name, if1=hostapd_if)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

        del wd

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

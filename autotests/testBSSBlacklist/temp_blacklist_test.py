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

from wiphy import wiphy_map
from hwsim import Hwsim

import time

class Test(unittest.TestCase):

    def test_connection_success(self):
        hwsim = Hwsim()

        bss_radio = [None, None, None]
        bss_hostapd = [None, None, None]

        for wname in wiphy_map:
            wiphy = wiphy_map[wname]
            intf = list(wiphy.values())[0]

            if intf.config and '1' in intf.config:
                bss_idx = 0
            elif intf.config and '2' in intf.config:
                bss_idx = 1
            elif intf.config and '3' in intf.config:
                bss_idx = 2
            else:
                continue

            for path in hwsim.radios:
                radio = hwsim.radios[path]
                if radio.name == wname:
                    break

            bss_radio[bss_idx] = radio
            bss_hostapd[bss_idx] = HostapdCLI(intf)

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio[0].addresses[0]
        rule0.bidirectional = True
        rule0.signal = -8000

        rule1 = hwsim.rules.create()
        rule1.source = bss_radio[1].addresses[0]
        rule1.bidirectional = True
        rule1.signal = -2500

        rule2 = hwsim.rules.create()
        rule2.source = bss_radio[2].addresses[0]
        rule2.bidirectional = True
        rule2.signal = -2000

        wd = IWD(True, '/tmp')

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        dev1, dev2 = wd.list_devices(2)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev1, condition)

        dev1.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev1, condition)

        ordered_network = dev1.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        self.assertIn(dev1.address, bss_hostapd[2].list_sta())

        # dev1 now connected, this should max out the first AP, causing the next
        # connection to fail to this AP.

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev2, condition)

        dev2.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev2, condition)

        ordered_network = dev2.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        # We should have temporarily blacklisted the first BSS, and connected
        # to this one.
        self.assertIn(dev2.address, bss_hostapd[1].list_sta())

        # Now check that the first BSS is still not blacklisted. We can
        # disconnect dev1, opening up the AP for more connections
        dev1.disconnect()
        dev2.disconnect()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev2, condition)

        dev2.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev2, condition)

        ordered_network = dev2.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        self.assertIn(dev2.address, bss_hostapd[2].list_sta())

        wd.unregister_psk_agent(psk_agent)

        del wd

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('main.conf')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

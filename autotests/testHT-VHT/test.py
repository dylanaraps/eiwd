#! /usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI, hostapd_map
import testutil
from time import sleep

class Test(unittest.TestCase):
    def do_connect(self, wd, device, hostapd):
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('testSSID')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        sleep(1)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hostapd.ifname)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_connection_success(self):
        hwsim = Hwsim()
        non_ht_hostapd = None
        ht_hostapd = None
        non_ht_radio = None
        ht_radio = None
        vht_radio = None

        for intf in hostapd_map.values():
            for path in hwsim.radios:
                radio = hwsim.radios[path]
                if radio.name == intf.wiphy.name:
                    break

            if intf.config == 'non-ht-vht.conf':
                non_ht_hostapd = HostapdCLI(intf)
                non_ht_radio = radio
            elif intf.config == 'ht.conf':
                ht_hostapd = HostapdCLI(intf)
                ht_radio = radio
            elif intf.config == 'vht.conf':
                vht_hostapd = HostapdCLI(intf)
                vht_radio = radio
            else:
                continue

        self.assertIsNotNone(non_ht_hostapd)
        self.assertIsNotNone(ht_hostapd)
        self.assertIsNotNone(vht_hostapd)

        rule0 = hwsim.rules.create()
        rule0.source = vht_radio.addresses[0]
        rule0.bidirectional = True
        rule0.signal = -2000

        rule1 = hwsim.rules.create()
        rule1.source = ht_radio.addresses[0]
        rule1.bidirectional = True
        rule1.signal = -2000

        rule2 = hwsim.rules.create()
        rule2.source = non_ht_radio.addresses[0]
        rule2.bidirectional = True
        rule2.signal = -2000

        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        device = wd.list_devices(1)[0]

        self.do_connect(wd, device, vht_hostapd)

        # lower VHT BSS signal, HT should now be preferred
        rule0.signal = -6000

        self.do_connect(wd, device, ht_hostapd)

        # lower HT BSS signal, basic rate BSS should now be preferred
        rule1.signal = -6000

        self.do_connect(wd, device, non_ht_hostapd)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

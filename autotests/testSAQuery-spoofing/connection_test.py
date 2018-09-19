#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI
from wiphy import wiphy_map

from time import sleep

class Test(unittest.TestCase):

    def test_connection_success(self):
        hwsim = Hwsim()

        hostapd = None
        radio = None

        for wname in wiphy_map:
            wiphy = wiphy_map[wname]
            intf = list(wiphy.values())[0]
            if intf.use == 'hostapd':
                hostapd = HostapdCLI(intf)
                for path in hwsim.radios:
                    if hwsim.radios[path].name == wname:
                        radio = hwsim.radios[path]
                        break

        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1);
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()
        ordered_network = ordered_networks[0]

        self.assertEqual(ordered_network.name, "ssidCCMP")
        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # TODO: for some reason hostapd does not respond to SA query if done
        #       too soon after connection.
        sleep(1)

        # Spoof a disassociate frame. This will kick off SA Query procedure.
        hwsim.spoof_disassociate(radio, hostapd.get_freq(), device.address)

        # sleep to ensure hostapd responds and SA Query does not timeout
        sleep(4)

        # Since disassociate was spoofed we should still be connected
        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

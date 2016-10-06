#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import DeviceState
from iwd import NetworkType

from hostapd import HostapdCLI

class Test(unittest.TestCase):

    def test_disconnect(self):
        wd = IWD()

        devices = wd.list_devices();
        self.assertIsNotNone(devices)
        device = devices[0]

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()
        o_net = ordered_networks[0]

        o_net.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        HostapdCLI.deauthenticate(device.address)

        condition = 'obj.state == DeviceState.connecting'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)


    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import DeviceState

from hostapd import HostapdCLI
from hostapd import hostapd_map

class Test(unittest.TestCase):

    def four_digit_pin_success(self, wd):

        devices = wd.list_devices(1)
        device = devices[0]
        pin = '1234'
        self.hostapd.wps_pin(pin)

        device.wps_start_pin(pin)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def test_connection_success(self):
        wd = IWD(True)

        self.four_digit_pin_success(wd)

    @classmethod
    def setUpClass(cls):
        cls.hostapd_if = list(hostapd_map.values())[0]
        cls.hostapd = HostapdCLI(cls.hostapd_if)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

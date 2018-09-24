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

    def test_push_button_success(self):
        self.hostapd.wps_push_button()

        wd = IWD()

        devices = wd.list_devices(1);
        device = devices[0]

        device.wps_push_button()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def test_pin_success(self):
        wd = IWD()

        devices = wd.list_devices(1);
        device = devices[0]
        pin = device.wps_generate_pin()
        self.hostapd.wps_pin(pin)

        device.wps_start_pin(pin)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def test_4_digit_pin_success(self):
        wd = IWD()

        devices = wd.list_devices(1);
        device = devices[0]
        pin = '1234'
        self.hostapd.wps_pin(pin)

        device.wps_start_pin(pin)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    @classmethod
    def setUpClass(cls):
        cls.hostapd_if = list(hostapd_map.values())[0]
        cls.hostapd = HostapdCLI(cls.hostapd_if)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

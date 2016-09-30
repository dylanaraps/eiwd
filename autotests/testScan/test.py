#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType

class Test(unittest.TestCase):

    def test_scan(self):
        wd = IWD()

        devices = wd.list_devices();
        self.assertIsNotNone(devices)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()

        seen = [0] * 3
        for o_n in ordered_networks:
            if o_n.name == "ssidOpen":
                self.assertEqual(o_n.type, NetworkType.open)
                if seen[0]:
                    raise Exception('Duplicated list entry')
                else:
                    seen[0] = 1
            elif o_n.name == "ssidTKIP":
                self.assertEqual(o_n.type, NetworkType.psk)
                if seen[1]:
                    raise Exception('Duplicated list entry')
                else:
                    seen[1] = 1
            elif o_n.name == "ssidCCMP":
                self.assertEqual(o_n.type, NetworkType.psk)
                if seen[2]:
                    raise Exception('Duplicated list entry')
                else:
                    seen[2] = 1
            else:
                raise Exception()

        for entry in seen:
            self.assertNotEqual(entry, 0)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)

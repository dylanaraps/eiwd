#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
import testutil
import os
from configparser import ConfigParser

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = IWD(True, '/tmp')

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('ssidCCMP')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

        psk_agent = PSKAgent('abc', ('domain\\user', 'testpasswd'))
        wd.register_psk_agent(psk_agent)

        ordered_network = device.get_ordered_network('Hotspot')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

        psk_freqs = None
        hs20_freqs = None
        config = ConfigParser()
        config.read('/var/lib/iwd/.known_network.freq')
        for s in config.sections():
            if os.path.basename(config[s]['name']) == 'ssidCCMP.psk':
                psk_freqs = config[s]['list']
                psk_freqs = psk_freqs.split(' ')
            elif os.path.basename(config[s]['name']) == 'example.conf':
                hs20_freqs = config[s]['list']
                hs20_freqs = hs20_freqs.split(' ')

        self.assertIsNotNone(psk_freqs)
        self.assertIn('5180', psk_freqs)
        self.assertIn('2412', psk_freqs)

        self.assertIsNotNone(hs20_freqs)
        self.assertIn('2412', hs20_freqs)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_hotspot('example.conf')
        conf = '[General]\ndisable_anqp=0\n'
        os.system('echo "%s" > /tmp/main.conf' % conf)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        os.remove('/tmp/main.conf')

if __name__ == '__main__':
    unittest.main(exit=True)

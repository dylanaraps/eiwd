#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

class Test(unittest.TestCase):

    def test_connection_success(self):
        networks = []

        wd = IWD(True)

        psk_agent = PSKAgent(["secret123"] * 4)
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(4)
        self.assertIsNotNone(devices)

        for d in devices:
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(d, condition)

            d.scan()

        for d in devices:
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(d, condition)

        for i in range(len(devices)):
            ordered_networks = devices[i].get_ordered_networks()

            network = [x for x in ordered_networks
                        if x.name == "ssidSAE-Clogging"][0]

            self.assertIsNotNone(network)
            self.assertEqual(network.name, "ssidSAE-Clogging")
            self.assertEqual(network.type, NetworkType.psk)

            networks.append(network)

            condition = 'not obj.connected'
            wd.wait_for_object_condition(network.network_object, condition)

        for n in networks:
            n.network_object.connect(wait=False)

        for n in networks:
            condition = 'obj.connected'
            wd.wait_for_object_condition(n.network_object, condition)

        for d in devices:
            d.wait_for_connected()

        for d in devices:
            d.disconnect()

        for n in networks:
            condition = 'not obj.connected'
            wd.wait_for_object_condition(n.network_object, condition)

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

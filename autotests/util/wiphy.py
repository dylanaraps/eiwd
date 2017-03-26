#! /usr/bin/python3
import os
import collections

wiphy_map = {}

Intf = collections.namedtuple('Intf',
        ['name', 'use', 'ctrl_interface', 'config'])

def parse_list():
    for entry in os.environ['TEST_WIPHY_LIST'].split('\n'):
        wname, ifname, use_str = entry.split('=', 2)

        if wname not in wiphy_map:
            wiphy_map[wname] = {}
        wiphy = wiphy_map[wname]

        use = use_str.split(',')

        intf = {}
        intf['name'] = ifname
        intf['use'] = use[0]
        intf['ctrl_interface'] = None
        intf['config'] = None
        intf.update(dict([param.split('=', 1) for param in use[1:]]))

        wiphy[ifname] = Intf(**intf)

parse_list()

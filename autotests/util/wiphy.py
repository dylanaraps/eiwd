#! /usr/bin/python3
import os
import collections

wiphy_map = {}

Wiphy = collections.namedtuple('Wiphy', ['name', 'use', 'interface_map'])

Intf = collections.namedtuple('Intf',
        ['name', 'wiphy', 'ctrl_interface', 'config'])

def parse_list():
    for entry in os.environ['TEST_WIPHY_LIST'].split('\n'):
        wname, use_str = entry.split('=', 1)
        use = use_str.split(',')

        if wname not in wiphy_map:
            wiphy_map[wname] = Wiphy(use=use[0], name=wname, interface_map={})

        if len(use) <= 1:
            continue

        intf = {}
        intf['name'] = None
        intf['wiphy'] = wiphy_map[wname]
        intf['ctrl_interface'] = None
        intf['config'] = None
        intf.update(dict([param.split('=', 1) for param in use[1:]]))

        wiphy_map[wname].interface_map[intf['name']] = Intf(**intf)

parse_list()

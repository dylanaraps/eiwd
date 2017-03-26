#!/usr/bin/python3
import os, os.path
import wiphy

hostapd_map = {ifname: intf for wname, wiphy in wiphy.wiphy_map.items()
        for ifname, intf in wiphy.items() if intf.use == 'hostapd'}

class HostapdCLI:
    def __init__(self, interface):
        self.ifname = interface.name
        self.ctrl_interface = interface.ctrl_interface

        socket_path = os.path.dirname(self.ctrl_interface)

        self.cmdline = 'hostapd_cli -p"' + socket_path + '" -i"' + \
                self.ifname + '"'

    def wps_push_button(self):
        os.system(self.cmdline + ' wps_pbc')

    def deauthenticate(self, client_address):
        os.system(self.cmdline + ' deauthenticate ' + client_address)

    @staticmethod
    def kill_all():
        os.system('killall hostapd')

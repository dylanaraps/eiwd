#!/usr/bin/python3
import os

class HostapdCLI:

    @staticmethod
    def wps_push_button():
        os.system('hostapd_cli wps_pbc')

    @staticmethod
    def deauthenticate(client_address):
        os.system('hostapd_cli deauthenticate ' + client_address)

    @staticmethod
    def kill_all():
        os.system('killall hostapd')

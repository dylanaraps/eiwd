#!/usr/bin/python3
import os

class HostapdCLI:

    @staticmethod
    def wps_push_button():
        os.system('hostapd_cli wps_pbc')

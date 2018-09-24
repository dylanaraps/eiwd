#!/usr/bin/python3
import os, os.path
import wiphy
import re
import socket

chan_freq_map = [
    None,
    2412,
    2417,
    2422,
    2427,
    2432,
    2437,
    2442,
    2447,
    2452,
    2457,
    2462,
    2467,
    2472,
    2484
]

hostapd_map = {ifname: intf for wname, wiphy in wiphy.wiphy_map.items()
        for ifname, intf in wiphy.items() if intf.use == 'hostapd'}

class HostapdCLI:
    def __init__(self, interface):
        self.ifname = interface.name
        self.ctrl_interface = interface.ctrl_interface

        self.socket_path = os.path.dirname(self.ctrl_interface)

        self.cmdline = 'hostapd_cli -p"' + self.socket_path + '" -i"' + \
                self.ifname + '"'

        self._hostapd_restarted = False

    def __del__(self):
        if self._hostapd_restarted:
            os.system('killall hostapd')

    def wps_push_button(self):
        os.system(self.cmdline + ' wps_pbc')

    def wps_pin(self, pin):
        os.system(self.cmdline + ' wps_pin any ' + pin)

    def deauthenticate(self, client_address):
        os.system(self.cmdline + ' deauthenticate ' + client_address)

    def eapol_reauth(self, client_address):
        cmd = 'IFNAME=' + self.ifname + ' EAPOL_REAUTH ' + client_address
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(self.socket_path + '/' + self.ifname)
        s.sendall(cmd.encode('utf-8'))
        s.close()

    def reload(self):
        # Seemingly all three commands needed for the instance to notice
        # interface's address change
        cmds = 'reload\ndisable\nenable\n'
        proc = os.popen(self.cmdline, mode='w')
        lines = proc.write(cmds)
        proc.close()

    def list_sta(self):
        proc = os.popen(self.cmdline + ' list_sta')
        lines = proc.read()
        proc.close()

        return [line for line in lines.split('\n') if line]

    def set_neighbor(self, addr, ssid, nr):
        os.system(self.cmdline + ' set_neighbor ' + addr + ' ssid=\\""' + ssid +
                    '"\\" nr=' + nr)

    def send_bss_transition(self, device, nr_list):
        # Send a BSS transition to a station (device). nr_list should be an
        # array of tuples containing the BSS address and neighbor report.
        # Parsing the neighbor report is a bit ugly but it makes it more
        # consistent with the set_neighbor() API, i.e. the same neighbor report
        # string could be used in both API's.
        pref = 1
        cmd = self.cmdline + ' bss_tm_req ' + device
        for i in nr_list:
            addr = i[0]
            nr = i[1]

            bss_info=str(int(nr[0:8], 16))
            op_class=str(int(nr[8:10], 16))
            chan_num=nr[10:12]
            phy_num=nr[14:16]

            cmd += ' pref=%s neighbor=%s,%s,%s,%s,%s' % \
                    (str(pref), addr, bss_info, op_class, chan_num, phy_num)
            pref += 1

        os.system(cmd)

    @staticmethod
    def kill_all():
        os.system('killall hostapd')

    def get_config_value(self, key):
        # first find the right config file
        for wname in hostapd_map:
            if wname == self.ifname:
                with open(hostapd_map[wname].config, 'r') as f:
                    # read in config file and search for key
                    cfg = f.read();
                    match = re.search(r'%s=.*' % key, cfg)
                    if match:
                        return match.group(0).split('=')[1]
        return None

    def get_freq(self):
        return chan_freq_map[int(self.get_config_value('channel'))]

    def ungraceful_restart(self):
        '''
            Ungracefully kill and restart hostapd
        '''
        for wname in wiphy.wiphy_map:
            name = wiphy.wiphy_map[wname]
            intf = list(name.values())[0]
            if intf.use == 'hostapd':
                os.system('killall -9 hostapd')
                os.system('ifconfig %s down' % intf.name)
                os.system('ifconfig %s up' % intf.name)
                os.system('hostapd -g %s -i %s %s &' %
                          (intf.ctrl_interface, intf.name, intf.config))
                break;

        # set flag so hostapd can be killed after the test
        self._hostapd_restarted = True

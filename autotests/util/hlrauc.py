import socket
import os
import threading
from Crypto.Cipher import AES

class AuthCenter:
    '''
        Home Location Register (HLR) and Authentication Center (AuC) used for
        for retrieving SIM/AKA values. This provides a UDP server that
        hostapd can communicate with to obtain SIM values.
    '''
    def __init__(self, sock_path, config_file):
        self._read_config(config_file)
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._socket.setblocking(0)
        if os.path.isfile(sock_path):
            os.unlink(sock_path)
        self._socket.bind(sock_path)

        self._rxhandle = threading.Thread(target=self._rx_thread)
        self._rxhandle.shutdown = False
        self._rxhandle.start()

    def _rx_thread(self):
        while (True):
            if self._rxhandle.shutdown == True:
                break
            try:
                data, addr = self._socket.recvfrom(1000)
                data = data.decode('ascii')
                resp = self._process_data(data)
            except:
                continue
            if resp:
                self._socket.sendto(bytearray(resp, 'UTF-8'), addr)

    def _read_config(self, file):
        self._database = {}
        with open(file) as f:
            for line in f:
                if line[0] == '#':
                    continue
                else:
                    data = line.split(':')
                    self._database[data[0]] = ':'.join(data[1:])

    def _process_data(self, data):
        if data[:12] == "SIM-REQ-AUTH":
            # SIM requests just return the stored values for the IMSI
            imsi, num_chals = data[13:].split(' ')
            data = self._database[imsi]

            response = "SIM-RESP-AUTH %s" % imsi
            response += (' ' + data)*int(num_chals)

            return response

    def stop(self):
        '''
            Stop the Authentication server and close the socket
        '''
        self._rxhandle.shutdown = True
        self._rxhandle.join()
        self._socket.close()

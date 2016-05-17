#!/usr/bin/python3

#built-in python libraries
import unittest
from gi.repository import GLib
import dbus
import time
import logging
import os
from random import randrange
from subprocess import Popen
import sys
sys.path.append('../utility') #needed to import all the utility modules
import utility

def defineAgentVars():
    global manager, pathAgent
    bus = dbus.SystemBus()
    pathAgent = "/connectToNetwork/agent/" + str(randrange(100))
    manager = dbus.Interface(bus.get_object('net.connman.iwd', "/"),
                          'net.connman.iwd.Manager')

def getManager():
    return manager

def getPathAgent():
    return pathAgent

class TestConnectDisconnect(unittest.TestCase):
    def doConnectDisconnect(self):
        deviceList = utility.getDeviceList(bus)
        networkList = utility.getNetworkList(deviceList, bus)
        utility.printNetworkInfo(networkList)
        networkToConnect = utility.getNetworkToConnectTo(networkList)

        # check if networkToConnect is not null. If yes, restart program
        # so that the network list is updated. Alternatively, we can scan
        # for networks.
        if (networkToConnect == ""):
            time.sleep(2)
            logger.debug("RESTART PROGRAM")
            os.execl(sys.executable, sys.executable, * sys.argv)

        self.assertNotEqual(networkToConnect, "")
        # start simpleAgent
        proc = Popen([sys.executable, './simpleAgent.py'])
        time.sleep(2)
        network = dbus.Interface(bus.get_object("net.connman.iwd",
                                            networkToConnect),
                                            "net.connman.iwd.Network")
        status = utility.connect(networkToConnect, self, mainloop, bus)
        if status == False:
            #terminate proc
            proc.terminate()
            return

        logger.info("Currently connected to: %s",
                    utility.getCurrentlyConnectedNetworkName())
        self.assertEqual(utility.getCurrentlyConnectedNetworkName(), "IntelWIFI")

        # retrieve the deviceId form networkToConnect. This will be used
        # for checking if we are disconnecting from the right device later.
        deviceIdIndex = networkToConnect.rfind("/", 0,
                                               len(networkToConnect))
        deviceIdOfConnectedNetwork = networkToConnect[0:deviceIdIndex]
        logger.debug("device id of connected network %s",
                     deviceIdOfConnectedNetwork)

        # wait 2 seconds before initiating disconnect
        time.sleep(2)
        deviceIdToDisconnect = utility.getCurrentlyConnectedDevice()
        logger.info("Disconnecting from: %s", deviceIdToDisconnect)
        self.assertEqual(deviceIdToDisconnect, deviceIdOfConnectedNetwork)
        utility.disconnect(deviceIdToDisconnect, mainloop, bus)
        #terminate proc
        proc.terminate()

    # connect to network A. Wait for 2 seconds. Disconnect.
    def test_connectDisconnect(self):
        logger.info(sys._getframe().f_code.co_name)
        while (True):
            if bus.name_has_owner('net.connman.iwd') == True:
                break
        self.doConnectDisconnect()
        #watch doesn't seem to work. So used name_has_owner
        #watch = bus.watch_name_owner("net.connman.iwd",self.doConnectDisconnect)

    @classmethod
    def setUpClass(cls):
        global logger, bus, mainloop
        utility.initLogger()
        logger = logging.getLogger(__name__)
        bus = dbus.SystemBus()
        mainloop = GLib.MainLoop()

    @classmethod
    def tearDownClass(cls):
        mainloop.quit()

if __name__ == '__main__':
    unittest.main(exit=True)

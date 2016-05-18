#!/usr/bin/python3

#built-in python libraries
import unittest
from gi.repository import GLib
import dbus
import dbus.service
import dbus.mainloop.glib
import time
import threading
import logging
from random import randrange
from subprocess import Popen
import sys
import os
sys.path.append('../utility') #needed to import all the utlilty modules
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

def getSecondNetworkToConnect(networkList, firstNetworkName):
    logger.debug(sys._getframe().f_code.co_name)
    for networkInfo in networkList:
        properties = networkList[networkInfo]
        for key in properties.keys():
            val = properties[key]
            # skip the first connected network
            if (properties["Name"] == firstNetworkName):
                continue
            return networkInfo
    return ""

class TestTwoNetworks(unittest.TestCase):
    # connect to network A. disconnect from network A.
    # connect to network B. disconnect from network B.
    def connectToNetwork(self, networkToConnect):
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

        connectedNetworkName = utility.getCurrentlyConnectedNetworkName()
        logger.info("Currently connected to: %s", connectedNetworkName)
        self.assertIn(connectedNetworkName, networkListToMatch)
        # remove the network we just matched from the list
        networkListToMatch.remove(connectedNetworkName)

        # wait 2 seconds before initiating disconnect
        time.sleep(2)
        # retrieve the deviceId form networkToConnect. This will be used
        # for checking if we are disconnecting from the right device later.
        deviceIdIndex = networkToConnect.rfind("/", 0,
                                               len(networkToConnect))
        deviceIdOfConnectedNetwork = networkToConnect[0:deviceIdIndex]

        deviceIdToDisconnect = utility.getCurrentlyConnectedDevice()
        logger.info("Disconnecting from: %s", deviceIdToDisconnect)
        self.assertEqual(deviceIdToDisconnect, deviceIdOfConnectedNetwork)
        utility.disconnect(deviceIdToDisconnect, mainloop, bus)
        #terminate proc
        proc.terminate()
        return connectedNetworkName

    def doConnectDisconnectTwoNetworks(self):
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
        # connect to 1st network
        connectedNetworkName = self.connectToNetwork(networkToConnect)

        # connect to the 2nd network
        secondNetworkToConnect = getSecondNetworkToConnect(networkList,
                                                           connectedNetworkName)
        connectedNetworkName = self.connectToNetwork(secondNetworkToConnect)

    def test_twoNetworks(self):
        logger.info(sys._getframe().f_code.co_name)
        while (True):
            if bus.name_has_owner('net.connman.iwd') == True:
                break
        self.doConnectDisconnectTwoNetworks()

    @classmethod
    def setUpClass(cls):
        global logger, bus, mainloop, networkListToMatch
        utility.initLogger()
        logger = logging.getLogger(__name__)
        mainloop = GLib.MainLoop()
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus = dbus.SystemBus()
        # we should connect to these networks - in any order
        networkListToMatch = ["IntelWIFI", "PersonalWIFI"]

    @classmethod
    def tearDown(self):
        mainloop.quit()

if __name__ == '__main__':
    unittest.main(exit=True)

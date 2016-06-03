#!/usr/bin/python3

import sys
import dbus
import logging
import traceback

IWD_SERVICE =                   'net.connman.iwd'

IWD_AGENT_MANAGER_INTERFACE =   'net.connman.iwd.AgentManager'
IWD_DEVICE_INTERFACE =          'net.connman.iwd.Device'
IWD_NETWORK_INTERFACE =         'net.connman.iwd.Network'
IWD_AGENT_INTERFACE =           'net.connman.iwd.Agent'
IWD_WSC_INTERFACE =             'net.connman.iwd.WiFiSimpleConfiguration'

IWD_TOP_LEVEL_PATH = "/"

# get all the available networks
def getObjectList(bus):
    logger.debug(sys._getframe().f_code.co_name)
    manager = dbus.Interface(bus.get_object(IWD_SERVICE, "/"),
                                        "org.freedesktop.DBus.ObjectManager")
    return manager.GetManagedObjects()

# get all the available networks
def getNetworkList(objects, bus):
    logger.debug(sys._getframe().f_code.co_name)
    networkList = []
    for path in objects:
        if IWD_DEVICE_INTERFACE not in objects[path]:
            continue
        for path2 in objects:
            if not path2.startswith(path) or \
                IWD_NETWORK_INTERFACE not in objects[path2]:
                    continue
            networkList.append(path2)
        return networkList

def connect(networkToConnect, self, mainloop, bus):
    logger.debug(sys._getframe().f_code.co_name)
    logger.debug("    %s", networkToConnect)
    network = dbus.Interface(bus.get_object(IWD_SERVICE, networkToConnect),
                                            IWD_NETWORK_INTERFACE)
    try:
        network.Connect()
    except:
        errorMsg = "Could not connect to network %s", networkToConnect
        logger.error(traceback.print_exc(file=sys.stdout))
        self.assertTrue(False, errorMsg)
        return False

    logger.info("Successfully connected to: %s", networkToConnect)
    return True

# try to disconnect from the device.
def disconnect(deviceToDisconnect, mainloop, bus):
    logger.debug(sys._getframe().f_code.co_name)
    device = dbus.Interface(bus.get_object(IWD_SERVICE, deviceToDisconnect),
                                           IWD_DEVICE_INTERFACE)
    try:
        device.Disconnect()
    except:
        errorMsg = "Failed to disconnect from device %s", deviceToDisconnect
        logger.error(traceback.print_exc(file=sys.stdout))
        assertTrue(False, errorMsg)
        return False

    logger.info("Successfully disconnected from: %s", deviceToDisconnect)
    return True

# get the 1st network found to connect to
def getNetworkToConnectTo(objects):
    logger.debug(sys._getframe().f_code.co_name)
    networkList = []
    for path in objects:
        for path2 in objects:
            if not path2.startswith(path) or \
                IWD_NETWORK_INTERFACE not in objects[path2]:
                    continue
            return path2
    return ""

# return the currently connected device by
# checking the 'ConnectedNetwork' property
def getCurrentlyConnectedDevice():
    logger.debug(sys._getframe().f_code.co_name)
    bus = dbus.SystemBus()
    manager = dbus.Interface(bus.get_object(IWD_SERVICE, "/"),
                                        "net.connman.iwd.Manager")
    objects = getObjectList(bus)
    for path in objects:
        if IWD_DEVICE_INTERFACE not in objects[path]:
            continue
        device = objects[path][IWD_DEVICE_INTERFACE]
        for key in device.keys():
            if key in ["ConnectedNetwork"]:
                return path
    return ""

# get name of the network currently connected to
def getCurrentlyConnectedNetworkName():
    logger.debug(sys._getframe().f_code.co_name)
    bus = dbus.SystemBus()
    deviceList = getObjectList(bus)
    networkList = getNetworkList(deviceList, bus)
    for path in deviceList:
        for path2 in deviceList:
            if not path2.startswith(path) or \
                IWD_NETWORK_INTERFACE not in deviceList[path2]:
                continue
            network = deviceList[path2][IWD_NETWORK_INTERFACE]
            for key in network.keys():
                name = ""
                if key in ["Connected"]:
                    # this check is needed in case when we are testing
                    # connectivity with multiple networks. The previously
                    # connected network will still have the 'Connected' property
                    # even though it will be set to 0.
                    val = network[key]
                    if network[key] == 0: # if "Connected is 0"
                        continue
                    for key2 in network.keys():
                        if key2 in ["Name"]:
                            return network[key2]
    return ""

# get name of the network
def getNetworkName(deviceList):
    logger.debug(sys._getframe().f_code.co_name)
    for path in deviceList:
        if IWD_DEVICE_INTERFACE not in deviceList[path]:
            continue
        for path2 in deviceList:
            if not path2.startswith(path) or \
                IWD_NETWORK_INTERFACE not in deviceList[path2]:
                continue
            network = deviceList[path2][IWD_NETWORK_INTERFACE]
            for key in network.keys():
                if key in ["Name"]:
                    return network[key]
    return ""

def initLogger():
    global logger
    logger = logging.getLogger(__name__)
    # logging levels include DEBUG, INFO, WARNING, ERROR, CRITICAL
    logging.basicConfig(level=logging.DEBUG)

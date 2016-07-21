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
        if IWD_NETWORK_INTERFACE not in objects[path]:
            continue
        networkList.append(path)
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
        if IWD_NETWORK_INTERFACE not in objects[path]:
            continue
        return path
    return ""

# return the current connection status
# connected, disconnected, connecting, disconnecting
def getConnectionStatus():
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
            if key in ["State"]:
                logger.debug("Device state is %s", device["State"])
                if device["State"] in "connected":
                    return True
        return False

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
    for path in deviceList:
        if IWD_NETWORK_INTERFACE not in deviceList[path]:
            continue
        network = deviceList[path][IWD_NETWORK_INTERFACE]
        # this check is needed in case when we are testing
        # connectivity with multiple networks. The previously
        # connected network will still have the 'Connected' property
        # even though it will be set to 0.
        if not network["Connected"]: # if "Connected is 0"
            continue
        return network["Name"]
    return ""

# get name of the network
def getNetworkName(deviceList):
    logger.debug(sys._getframe().f_code.co_name)
    for path in deviceList:
        if IWD_NETWORK_INTERFACE not in deviceList[path]:
            continue
        network = deviceList[path][IWD_NETWORK_INTERFACE]
        return network["Name"]
    return ""

def initLogger():
    global logger
    logger = logging.getLogger(__name__)
    # logging levels include DEBUG, INFO, WARNING, ERROR, CRITICAL
    logging.basicConfig(level=logging.DEBUG)

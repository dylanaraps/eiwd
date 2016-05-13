#!/usr/bin/python3

import sys
import dbus
import logging
import traceback

# get all the available networks
def getDeviceList(bus):
    logger.debug(sys._getframe().f_code.co_name)
    manager = dbus.Interface(bus.get_object("net.connman.iwd", "/"),
                                        "net.connman.iwd.Manager")
    return manager.GetDevices()

# get all the available networks
def getNetworkList(devices, bus):
    logger.debug(sys._getframe().f_code.co_name)
    for path in devices:
        device = dbus.Interface(bus.get_object("net.connman.iwd", path),
                                    "net.connman.iwd.Device")
        return device.GetNetworks()

# try to connect to the network.
def connect(networkToConnect, self, mainloop, bus):
    logger.debug(sys._getframe().f_code.co_name)
    logger.debug("    %s", networkToConnect)
    network = dbus.Interface(bus.get_object("net.connman.iwd",networkToConnect),
                                            "net.connman.iwd.Network")
    try:
        network.Connect()
    except:
        errorMsg = "Could not connect to network %s", networkToConnect
        logger.error(traceback.print_exc(file=sys.stdout))
        self.assertTrue(False, errorMsg)

    logger.info("Successfully connected to: %s", networkToConnect)

# try to disconnect from the device.
def disconnect(deviceToDisconnect, mainloop, bus):
    logger.debug(sys._getframe().f_code.co_name)
    device = dbus.Interface(bus.get_object("net.connman.iwd",deviceToDisconnect),
                                           "net.connman.iwd.Device")
    try:
        device.Disconnect()
    except:
        errorMsg = "Failed to disconnect from device %s", deviceToDisconnect
        logger.error(traceback.print_exc(file=sys.stdout))
        assertTrue(False, errorMsg)

    logger.info("Successfully disconnected from: %s", deviceToDisconnect)

# get the 1st network found to connect to
def getNetworkToConnectTo(networkList):
    logger.debug(sys._getframe().f_code.co_name)
    for networkInfo in networkList:
        logger.debug("    %s", networkInfo)
        return networkInfo
    return ""

# return the currently connected device by
# checking the 'ConnectedNetwork' property
def getCurrentlyConnectedDevice():
    logger.debug(sys._getframe().f_code.co_name)
    bus = dbus.SystemBus()
    manager = dbus.Interface(bus.get_object("net.connman.iwd", "/"),
                                        "net.connman.iwd.Manager")
    devices = manager.GetDevices()
    for path in devices:
        properties = devices[path]
        for key in properties.keys():
            if key in ["ConnectedNetwork"]:
                    return path
    return ""

# get name of the network currently connected to
def getCurrentlyConnectedNetworkName():
    logger.debug(sys._getframe().f_code.co_name)
    bus = dbus.SystemBus()
    deviceList = getDeviceList(bus)
    networkList = getNetworkList(deviceList, bus)
    for path in networkList:
            properties = networkList[path]
            for key in properties.keys():
                if key in ["Connected"]:
                    # this check is needed in case when we are testing
                    # connectivity with multiple networks. The previously
                    # connected network will still have the 'Connected' property
                    # even though it will be set to 0.
                    if properties["Connected"] == 0:
                        continue
                    return properties["Name"]
    return ""

# get name of the network
def getNetworkName(networkList):
    logger.debug(sys._getframe().f_code.co_name)
    for network in networkList:
            properties = networkList[network]
            return properties["Name"]
    return ""

# print information about all the networks found
def printNetworkInfo(networkList):
    logger.debug(sys._getframe().f_code.co_name)
    for path in networkList:
            logger.debug("    [ %s ]" % path)
            properties = networkList[path]
            for key in properties.keys():
                if key in ["SSID"]:
                    val = properties[key]
                    val = "".join(map(chr, val))
                else:
                    val = properties[key]

                logger.info("        %s = %s" % (key, val))

def initLogger():
    global logger
    logger = logging.getLogger(__name__)
    # logging levels include DEBUG, INFO, WARNING, ERROR, CRITICAL
    logging.basicConfig(level=logging.DEBUG)

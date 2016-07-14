#!/usr/bin/python3

#built-in python libraries
from gi.repository import GLib
import dbus
import dbus.service
import dbus.mainloop.glib
import logging
import traceback
import threading
import time
import sys
sys.path.append('../utility') #needed to import all the utlilty modules
import utility
from random import randrange

def defineAgentVars():
    global manager, pathAgent
    bus = dbus.SystemBus()
    pathAgent = "/utility/agent/" + str(randrange(100))
    manager = dbus.Interface(bus.get_object(utility.IWD_SERVICE, "/"),
                             utility.IWD_AGENT_MANAGER_INTERFACE)

def getManager():
    return manager

def getPathAgent():
    return pathAgent

class Agent(dbus.service.Object):
    @dbus.service.method(utility.IWD_AGENT_INTERFACE,
                            in_signature='', out_signature='')
    def Release(self):
        logger.debug("Release")
        mainloop.quit()

    @dbus.service.method(utility.IWD_AGENT_INTERFACE,
                            in_signature='o',
                            out_signature='s')
    def RequestPassphrase(self, path):
        utility.initLogger()
        logger = logging.getLogger(__name__)
        logger.info("RequestPassphrase")
        return 'EasilyGuessedPassword'

def startAgent(mainloop):
    mainloop.run()

def registerAgent(bus, mainloop):
    defineAgentVars()
    manager = getManager()
    pathAgent = getPathAgent()
    object = Agent(bus, pathAgent)
    try:
        manager.RegisterAgent(pathAgent)
        logger.debug("Registered iwd agent")
        # this will be received by stdout in the parent
        print("AGENT_REGISTERED")
    except:
        logger.debug("Error in registering path")
        logger.debug(traceback.print_exc(file=sys.stdout))

    threading.Thread(target=delayedUnregister, args=(manager, pathAgent,
                                                       mainloop,)).start()

def unregisterAgent(manager, pathAgent):
    try:
        manager.UnregisterAgent(pathAgent)
        logger.debug("UnRegistered iwd agent")
    except:
        logger.debug("Error in unregistering path")
        logger.debug(traceback.print_exc(file=sys.stdout))

def delayedUnregister(manager, path, mainloop):
    counter = 1
    while (utility.getCurrentlyConnectedDevice() == "" and counter < 10):
         time.sleep(1)
         counter += 1
         continue

    time.sleep(1)
    unregisterAgent(manager, path)
    mainloop.quit()

def init():
    global logger
    utility.initLogger()
    logger = logging.getLogger(__name__)
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    mainloop = GLib.MainLoop()
    registerAgent(bus, mainloop)
    threading.Thread(target=startAgent, args=(mainloop,)).start()

if __name__ == '__main__':
    init()

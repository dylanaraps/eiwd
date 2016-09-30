#!/usr/bin/python3
from gi.repository import GLib

import dbus
import dbus.service
import dbus.mainloop.glib
import sys
import os
import threading
import time

from abc import ABCMeta, abstractmethod
from enum import Enum

IWD_STORAGE_DIR =               '/var/lib/iwd'

DBUS_OBJECT_MANAGER =           'org.freedesktop.DBus.ObjectManager'
DBUS_PROPERTIES =               'org.freedesktop.DBus.Properties'

IWD_SERVICE =                   'net.connman.iwd'
IWD_WIPHY_INTERFACE =           'net.connman.iwd.Adapter'
IWD_AGENT_INTERFACE =           'net.connman.iwd.Agent'
IWD_AGENT_MANAGER_INTERFACE =   'net.connman.iwd.AgentManager'
IWD_DEVICE_INTERFACE =          'net.connman.iwd.Device'
IWD_KNOWN_NETWORKS_INTERFACE =  'net.connman.iwd.KnownNetworks'
IWD_NETWORK_INTERFACE =         'net.connman.iwd.Network'
IWD_WSC_INTERFACE =             'net.connman.iwd.WiFiSimpleConfiguration'

IWD_AGENT_MANAGER_PATH =        '/'
IWD_KNOWN_NETWORKS_PATH =       '/'
IWD_TOP_LEVEL_PATH =            '/'


dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)


class UnknownDBusEx(Exception): pass
class InProgressEx(dbus.DBusException): pass
class FailedEx(dbus.DBusException): pass
class AbortedEx(dbus.DBusException): pass
class NotAvailableEx(dbus.DBusException): pass
class InvalidArgsEx(dbus.DBusException): pass
class AlreadyExistsEx(dbus.DBusException): pass
class NotFoundEx(dbus.DBusException): pass
class NotSupportedEx(dbus.DBusException): pass
class NoAgentEx(dbus.DBusException): pass
class NotConnectedEx(dbus.DBusException): pass
class NotImplementedEx(dbus.DBusException): pass
class CanceledEx(dbus.DBusException):
    _dbus_error_name = 'net.connman.iwd.Error.Canceled'


_dbus_ex_to_py = {
    'Canceled' :        CanceledEx,
    'InProgress' :      InProgressEx,
    'Failed' :          FailedEx,
    'Aborted' :         AbortedEx,
    'NotAvailable' :    NotAvailableEx,
    'InvalidArgs' :     InvalidArgsEx,
    'AlreadyExists' :   AlreadyExistsEx,
    'NotFound' :        NotFoundEx,
    'NotSupported' :    NotSupportedEx,
    'NoAgent' :         NoAgentEx,
    'NotConnected' :    NotConnectedEx,
    'NotImplemented' :  NotImplementedEx,
}


def _convert_dbus_ex(dbus_ex):
    ex_name = dbus_ex.get_dbus_name()
    ex_short_name = ex_name[ex_name.rfind(".") + 1:]
    if ex_short_name in _dbus_ex_to_py:
        return _dbus_ex_to_py[ex_short_name](dbus_ex)
    else:
        return UnknownDBusEx(ex_name + ': ' + dbus_ex.get_dbus_message())


class AsyncOpAbstract(object):
    __metaclass__ = ABCMeta

    _is_completed = False
    _exception = None

    def _success(self):
        self._is_completed = True

    def _failure(self, ex):
        self._is_completed = True
        self._exception = _convert_dbus_ex(ex)

    def _wait_for_async_op(self):
        context = mainloop.get_context()
        while not self._is_completed:
            if context.pending():
                context.iteration()
            else:
                time.sleep(0.01)

        self._is_completed = False
        if self._exception is not None:
            raise self._exception


class IWDDBusAbstract(AsyncOpAbstract):
    __metaclass__ = ABCMeta

    _bus = dbus.SystemBus()

    def __init__(self, object_path = None, properties = None):
        self._object_path = object_path
        proxy = self._bus.get_object(IWD_SERVICE, self._object_path)
        self._iface = dbus.Interface(proxy, self._iface_name)
        self._prop_proxy = dbus.Interface(proxy, DBUS_PROPERTIES);

        if properties is None:
            self._properties = self._prop_proxy.GetAll(self._iface_name)
        else:
            self._properties = properties

        self._prop_proxy.connect_to_signal("PropertiesChanged",
                                           self._property_changed_handler,
                                           DBUS_PROPERTIES,
                                           path_keyword="path")

    def _property_changed_handler(self, interface, changed, invalidated, path):
        if interface == self._iface_name and path == self._object_path:
            for name, value in changed.items():
                self._properties[name] = value

    @abstractmethod
    def __str__(self):
        pass


class DeviceState(Enum):
    '''Conection state of a device'''
    connected =     'connected'
    disconnected =  'disconnected'
    connecting =    'connecting'
    disconnecting = 'disconnecting'

    def __str__(self):
        return self.value

    @classmethod
    def from_str(cls, string):
        return getattr(cls, string, None)


class NetworkType(Enum):
    '''Network security type'''
    open =  'open'
    psk =   'psk'
    eap =   '8021x'

    def __str__(self):
        return str(self.value)

    @classmethod
    def from_string(cls, string):
        type = None
        for attr in dir(cls):
            if (str(getattr(cls, attr)) == string):
                type = getattr(cls, attr)
                break
        return type


class Device(IWDDBusAbstract):
    '''
        Class represents a network device object: net.connman.iwd.Device
        with its properties and methods
    '''
    _iface_name = IWD_DEVICE_INTERFACE

    @property
    def device_path(self):
        '''
            Device's dbus path.

            @rtype: string
        '''
        return self._object_path

    @property
    def name(self):
        '''
            Device's interface name.

            @rtype: string
        '''
        return self._properties['Name']

    @property
    def address(self):
        '''
            Interface's hardware address in the XX:XX:XX:XX:XX:XX format.

            @rtype: string
        '''
        return self._properties['Address']

    @property
    def state(self):
        '''
            Reflects the general network connection state.

            @rtype: object (State)
        '''
        return DeviceState.from_str(self._properties['State'])

    @property
    def connected_network(self):
        '''
            net.connman.iwd.Network object representing the
            network the device is currently connected to or to
            which a connection is in progress.

            @rtype: object (Network)
        '''
        return self._properties('ConnectedNetwork')

    @property
    def powered(self):
        '''
            True if the interface is UP. If false, the device's radio is
            powered down and no other actions can be performed on the device.

            @rtype: boolean
        '''
        return bool(self._properties['Powered'])

    @property
    def scanning(self):
        '''
        Reflects whether the device is currently scanning
        for networks.  net.connman.iwd.Network objects are
        updated when this property goes from true to false.

        @rtype: boolean
        '''
        return bool(self._properties['Scanning'])

    def scan(self):
        '''Schedule a network scan.

           Possible exception: BusyEx
                               FailedEx
        '''
        self._iface.Scan(dbus_interface=self._iface_name,
                               reply_handler=self._success,
                               error_handler=self._failure)

        self._wait_for_async_op()

    def disconnect(self):
        '''Disconnect from the network

           Possible exception: BusyEx
                               FailedEx
                               NotConnectedEx
        '''
        self._iface.Disconnect(dbus_interface=self._iface_name,
                               reply_handler=self._success,
                               error_handler=self._failure)

        self._wait_for_async_op()

    def get_ordered_networks(self):
        '''Return the list of networks found in the most recent
           scan, sorted by their user interface importance
           score as calculated by iwd.  If the device is
           currently connected to a network, that network is
           always first on the list, followed by any known
           networks that have been used at least once before,
           followed by any other known networks and any other
           detected networks as the last group.  Within these
           groups the maximum relative signal-strength is the
           main sorting factor.
        '''
        ordered_networks = []
        for bus_obj in self._iface.GetOrderedNetworks():
            ordered_network = OrderedNetwork(bus_obj)
            ordered_networks.append(ordered_network)
        return ordered_networks

    def __str__(self):
        return 'Device: ' + self.device_path + '\n'\
                '\tName:\t\t' + self.name + '\n'\
                '\tAddress:\t' + self.address + '\n'\
                '\tState:\t\t' + str(self.state) + '\n'\
                '\tPowered:\t' + str(self.powered) + '\n'
                #'\tConn-d net:\t' + str(self.connected_network) + '\n'


class Network(IWDDBusAbstract):
    '''Class represents a network object: net.connman.iwd.Network'''
    _iface_name = IWD_NETWORK_INTERFACE

    @property
    def name(self):
        '''
            Network SSID.

            @rtype: string
        '''
        return self._properties['Name']

    @property
    def connected(self):
        '''
            Reflects whether the device is connected to this network.

            @rtype: boolean
        '''
        return bool(self._properties['Connected'])

    def connect(self):
        '''
            Connect to the network. Request the device implied by the object
            path to connect to specified network.

			Possible exception: AbortedEx
                                BusyEx
                                FailedEx
                                NoAgentEx
                                NotSupportedEx
                                TimeoutEx

            @rtype: void
        '''

        self._iface.Connect(dbus_interface=self._iface_name,
                            reply_handler=self._success,
                            error_handler=self._failure)

        self._wait_for_async_op()

    def __str__(self, prefix = ''):
        return prefix + 'Network:\n' \
                + prefix + '\tName:\t' + self.name + '\n' \
                + prefix + '\tConnected:\t' + str(self.connected)


class KnownNetwork():
    '''Class represents a known network object.'''

    @property
    def name(self):
        '''Contains the Name (SSID) of the network.'''
        return self._name

    @property
    def type(self):
        '''Contains the type of the network.'''
        return self._type

    @property
    def last_connected_time(self):
        '''
        Contains the last time this network has been connected to.
        The time is given as a string in ISO 8601 format. If the network
        is known, but has never been successfully connected to,
        this attribute is set to None.

        @rtype: string
        '''
        return self._last_connected_time

    @property
    def last_seen_time(self):
        '''
        Contains the last time this network has been seen in scan results.

        @rtype: string
        '''
        return self._last_seen_time

    def __init__(self, n_n_object):
        self._name = n_n_object['Name']
        self._type = NetworkType.from_string(n_n_object['Type'])
        self._last_connected_time = n_n_object['LastConnectedTime']
        self._last_seen_time = n_n_object['LastSeenTime']

    def __str__(self):
        return 'Name' + self.name + ' Type' + self.type


class OrderedNetwork(object):
    '''Represents a network found in the scan'''

    def __init__(self, o_n_tuple):
        self._network_object = Network(o_n_tuple[0])
        self._name = o_n_tuple[1]
        self._signal_strength = o_n_tuple[2]
        self._type = NetworkType.from_string(o_n_tuple[3])

    @property
    def network_object(self):
        '''
            net.connman.iwd.Network object representing the network.

            @rtype: Network
        '''
        return self._network_object

    @property
    def name(self):
        '''
            Device's interface name.

            @rtype: string
        '''
        return self._name

    @property
    def signal_strength(self):
        '''
            Network's maximum signal strength expressed in 100 * dBm.
            The value is the range of 0 (strongest signal) to
            -10000 (weakest signal)

            @rtype: number
        '''
        return self._signal_strength

    @property
    def type(self):
        '''
            Contains the type of the network.

            @rtype: NetworkType
        '''
        return self._type

    def __str__(self):
        return 'Ordered Network:\n'\
                '\tName:\t\t' + self.name + '\n'\
                '\tNetwork Type:\t' + str(self.type) + '\n'\
                '\tSignal Strength:'\
                    + ('None' if self.signal_strength is None else\
                        str(self.signal_strength)) + '\n'\
                '\tObject: \n' + self.network_object.__str__('\t\t')


class PSKAgent(dbus.service.Object):

    def __init__(self, passphrase = None):
        self._passphrase = passphrase
        self._path = '/test/agent/' + str(int(round(time.time() * 1000)))

        dbus.service.Object.__init__(self, dbus.SystemBus(), self._path)

    @property
    def path(self):
        return self._path

    @dbus.service.method(IWD_AGENT_INTERFACE, in_signature='', out_signature='')
    def Release(self):
        print("Agent released")

    @dbus.service.method(IWD_AGENT_INTERFACE, in_signature='o',
                                                              out_signature='s')
    def RequestPassphrase(self, path):
        print('Requested passphrase for ' + path)

        if self._passphrase is None:
            raise CanceledEx("canceled")

        return self._passphrase

    @dbus.service.method(IWD_AGENT_INTERFACE, in_signature='s',
                                                               out_signature='')
    def Cancel(self, reason):
        print("Cancel: " + reason)


class IWD(AsyncOpAbstract):
    ''''''
    _bus = dbus.SystemBus()

    _object_manager_if = None
    _agent_manager_if = None
    _known_network_manager_if = None

    def __init__(self):
        global mainloop
        mainloop = GLib.MainLoop()

    @property
    def _object_manager(self):
        if self._object_manager_if is None:
            self._object_manager_if = \
                       dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                                           IWD_TOP_LEVEL_PATH),
                                      DBUS_OBJECT_MANAGER)
        return self._object_manager_if

    @property
    def _agent_manager(self):
        if self._agent_manager_if is None:
            self._agent_manager_if =\
                dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                                    IWD_AGENT_MANAGER_PATH),
                               IWD_AGENT_MANAGER_INTERFACE)
        return self._agent_manager_if

    @property
    def _known_network_manager(self):
        if self._known_network_manager_if is None:
            _known_network_manager_if =\
                dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                                    IWD_KNOWN_NETWORKS_PATH),
                                IWD_KNOWN_NETWORKS_INTERFACE)
        return _known_network_manager_if

    def wait_for_object_condition(self, obj, condition_str, max_wait = 15):
        start = time.time()
        context = mainloop.get_context()
        while not eval(condition_str):
            if context.pending():
                context.iteration()
            else:
                now = time.time()
                if (now - start) > max_wait:
                    raise TimeoutError('[' + condition_str + ']'\
                                       ' condition was not met in '\
                                       + str(max_wait) + ' sec')
                time.sleep(0.01)

    @staticmethod
    def clear_storage():
        os.system('rm -rf ' + IWD_STORAGE_DIR + '/*')

    @staticmethod
    def create_in_storage(file_name, file_content):
        fo = open(IWD_STORAGE_DIR + '/' + file_name, 'w')

        fo.write(file_content);
        fo.close()

    @staticmethod
    def copy_to_storage(source):
        import shutil

        assert not os.path.isabs(source)
        shutil.copy(source, IWD_STORAGE_DIR)

    def list_devices(self):
        objects = self._object_manager.GetManagedObjects()
        devices = None
        for path in objects.keys():
            interfaces = objects[path]
            for interface in interfaces.keys():
                if interface in [IWD_DEVICE_INTERFACE]:
                    if devices is None:
                        devices = []
                    device = Device(path)
                    devices.append(device)
        return devices

    def list_known_networks(self):
        '''Returns a list of KnownNetwork objects.'''
        known_network_list = []

        for n_n_object in self._known_network_manager.ListKnownNetworks():
            known_network = KnownNetwork(n_n_object)
            known_network_list.append(known_network)

        return known_network_list

    def forget_known_network(self, known_network):
        '''Removes the network from the 'known networks' list and
           removes any associated meta-data.  If the network is
           currently connected, then it is automatically disconnected'''
        self._known_network_manager.ForgetNetwork(
                                    known_network.name, known_network.type,
                                    dbus_interface=IWD_KNOWN_NETWORKS_INTERFACE,
                                    reply_handler=self._success,
                                    error_handler=self._failure)
        self._wait_for_async_op()

    def register_psk_agent(self, psk_agent):
        self._agent_manager.RegisterAgent(
                                     psk_agent.path,
                                     dbus_interface=IWD_AGENT_MANAGER_INTERFACE,
                                     reply_handler=self._success,
                                     error_handler=self._failure)
        self._wait_for_async_op()

    def unregister_psk_agent(self, psk_agent):
        self._agent_manager.UnregisterAgent(
                                     psk_agent.path,
                                     dbus_interface=IWD_AGENT_MANAGER_INTERFACE,
                                     reply_handler=self._success,
                                     error_handler=self._failure)
        self._wait_for_async_op()

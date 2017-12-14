import dbus
from gi.repository import GLib

SIM_AUTH_IFACE = 'org.ofono.SimAuthentication'

class Ofono(dbus.service.Object):
    def __init__(self):
        self._bus = dbus.SystemBus()

    def enable_modem(self, path):
        self._modem_path = path
        self._modem_iface = dbus.Interface(
                                        self._bus.get_object('org.ofono', path),
                                        'org.ofono.Modem')
        self._modem_iface.SetProperty("Powered", dbus.Boolean(1),
                                       timeout = 120)

    def _modem_prop_changed(self, property, changed):
        if property == 'Interfaces':
            if SIM_AUTH_IFACE in changed:
                self._sim_auth_up = True

    def wait_for_sim_auth(self, max_wait = 15):
        mainloop = GLib.MainLoop()
        self._sim_auth_up = False

        props = self._modem_iface.GetProperties()
        if SIM_AUTH_IFACE in props['Interfaces']:
            self._sim_auth_up = True
            return

        self._modem_iface.connect_to_signal('PropertyChanged',
                                             self._modem_prop_changed)

        self._wait_timed_out = False
        def wait_timeout_cb():
            self._wait_timed_out = True
            return False

        timeout = GLib.timeout_add_seconds(max_wait, wait_timeout_cb)
        context = mainloop.get_context()
        while (not self._sim_auth_up):
            context.iteration(may_block=True)
            if self._wait_timed_out:
                raise TimeoutError('waiting for SimAuthentication timed out')

        GLib.source_remove(timeout)

Pre-requisites:
1. Ensure you have hostapd installed.
2. Verify that the kernel has mac80211_hwsim.

Setup:
1. Create radios using mac80211_hwsim. For most tests, we need 2 radios.
    sudo modprobe mac80211_hwsim radios=2
2. Enable network interfaces:
    sudo ifconfig wlan0 up
    sudo ifconfig wlan1 up

Run tests (e.g. connectDisconnect test):
1. Start hostapd, with a config file as an argument.
    You can use the IntelWIFI.conf file in autotests/test1AP directory.
    sudo ./hostapd <path to autotests dir/test1AP/IntelWIFI.conf>
2. Start iwd.
    sudo iwd
3. Start connectDisconnect test (inside autotests directory).
    cd <iwd>/autotests/test1AP
    ./connectDisconnect.py

Note: This will not work with test-runner for now because of entropy issue. WIP.

Optional changes:
1. You can provide your own config file to hostapd. If so, then you would need to
    change the assert inside the test to the name of the ssid in your test.
    self.assertEqual(connectedNetworkName, "IntelWIFI")

twoNetworksTest: connect to network A. disconnect from network A.
                 connect to network B. disconnect from network B.

Start with test-runner:
   Test-runner looks at the hw.conf file and creates radios using
   hwsim and reads the conf file(s) defined under [HOSTAPD] section

1. Just start test-runner from under <iwd>/tools directory and it
   will automatically run the tests.
   cd <iwd>/tools
   sudo ./test-runner -t test2AP

Run stand-alone:
Pre-requisites:
1. Ensure you have hostapd installed.
2. Verify that the kernel has mac80211_hwsim.

Setup:
1. Create radios using mac80211_hwsim. For most tests, we need 3 radios.
    sudo modprobe mac80211_hwsim radios=3
2. Enable network interface:
    sudo ifconfig wlan2 up

Run test (e.g. twoNetworksTest test):
1. Start hostapd, with a config file as an argument.
    You can use the IntelWIFI.conf and PersonalWIFI.conf
    file in autotests/test2AP directory.
    sudo ./hostapd <path to autotests dir/test2AP/IntelWIFI.conf>
    sudo ./hostapd <path to autotests dir/test2AP/PersonalWIFI.conf>

Note: You might need to edit the *.conf file and change wln0 and wln1
      to wlan0 and wlan1 respectively.

2. Start iwd.
    sudo iwd
3. Start twoNetworksTest test (inside autotests/test2AP directory).
    cd <iwd>/autotests/test2AP
    ./twoNetworksTest.py

Optional changes:
1. You can provide your own config file to hostapd. If so, then you would need to
    change the assert inside the test to the name of the ssid in your test.
    self.assertEqual(connectedNetworkName, "IntelWIFI")

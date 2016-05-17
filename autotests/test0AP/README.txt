scanNetworkWithoutAPTest: This test checks that we do not find any AP to
                          connect to, if hostapd is not started.

Run tests (scanNetworkWithoutAPTest test):
1. Start iwd.
    sudo iwd
2. Start scanNetworkWithoutAPTest test (inside autotests/test0AP directory).
    cd <iwd>/autotests/test0AP
    ./scanNetworkWithoutAPTest.py

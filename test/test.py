import unittest
from datetime import datetime
from netaddr.core import AddrFormatError
from probequest.probe_request import ProbeRequest
from probequest.probe_request_sniffer import ProbeRequestSniffer

class TestProbeRequest(unittest.TestCase):
    def test_without_parameters(self):
        with self.assertRaises(TypeError):
            probe_req = ProbeRequest()

    def test_with_only_one_parameter(self):
        timestamp = 1517872027.0

        with self.assertRaises(TypeError):
            probe_req = ProbeRequest(timestamp)

    def test_with_only_two_parameters(self):
        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee:ff"

        with self.assertRaises(TypeError):
            probe_req = ProbeRequest(timestamp, s_mac)

    def test_create_a_probe_request(self):
        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee:ff"
        essid = "Test ESSID"

        probe_req = ProbeRequest(timestamp, s_mac, essid)

    def test_bad_mac_address(self):
        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee"
        essid = "Test ESSID"

        with self.assertRaises(AddrFormatError):
            probe_req = ProbeRequest(timestamp, s_mac, essid)

    def test_print_a_probe_request(self):
        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee:ff"
        essid = "Test ESSID"

        probe_req = ProbeRequest(timestamp, s_mac, essid)

        self.assertNotEqual(str(probe_req).find("Mon, 05 Feb 2018 23:07:07"), -1)
        self.assertNotEqual(str(probe_req).find("aa:bb:cc:dd:ee:ff (None) -> Test ESSID"), -1)

class TestProbeRequestSniffer(unittest.TestCase):
    def test_without_parameters(self):
        with self.assertRaises(TypeError):
            sniffer = ProbeRequestSniffer()

    def test_bad_display_function(self):
        with self.assertRaises(TypeError):
            sniffer = ProbeRequestSniffer("wlan0", display_func="Test")

    def test_bad_storage_function(self):
        with self.assertRaises(TypeError):
            sniffer = ProbeRequestSniffer("wlan0", storage_func="Test")

    def test_create_sniffer(self):
        sniffer = ProbeRequestSniffer("wlan0")

    def test_stop_before_start(self):
        sniffer = ProbeRequestSniffer("wlan0")
        sniffer.stop()

"""
Unit tests for the probe request module.
"""

import unittest
from time import localtime, strftime
from netaddr.core import AddrFormatError

from probequest.probe_request import ProbeRequest


class TestProbeRequest(unittest.TestCase):
    """
    Unit tests for the 'ProbeRequest' class.
    """

    def test_without_parameters(self):
        """
        Initialises a 'ProbeRequest' object without any parameter.
        """

        # pylint: disable=no-value-for-parameter

        with self.assertRaises(TypeError):
            _ = ProbeRequest()

    def test_with_only_one_parameter(self):
        """
        Initialises a 'ProbeRequest' object with only one parameter.
        """

        # pylint: disable=no-value-for-parameter

        timestamp = 1517872027.0

        with self.assertRaises(TypeError):
            _ = ProbeRequest(timestamp)

    def test_with_only_two_parameters(self):
        """
        Initialises a 'ProbeRequest' object with only two parameters.
        """

        # pylint: disable=no-value-for-parameter

        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee:ff"

        with self.assertRaises(TypeError):
            _ = ProbeRequest(timestamp, s_mac)

    def test_create_a_probe_request(self):
        """
        Creates a new 'ProbeRequest' with all the required parameters.
        """

        # pylint: disable=no-self-use

        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee:ff"
        essid = "Test ESSID"

        _ = ProbeRequest(timestamp, s_mac, essid)

    def test_bad_mac_address(self):
        """
        Initialises a 'ProbeRequest' object with a malformed MAC address.
        """

        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee"
        essid = "Test ESSID"

        with self.assertRaises(AddrFormatError):
            probe_req = ProbeRequest(timestamp, s_mac, essid)
            _ = probe_req.s_mac_oui

    def test_print_a_probe_request(self):
        """
        Initialises a 'ProbeRequest' object and prints it.
        """

        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee:ff"
        essid = "Test ESSID"

        probe_req = ProbeRequest(timestamp, s_mac, essid)

        self.assertNotEqual(
            str(probe_req).find(
                strftime("%a, %d %b %Y %H:%M:%S %Z", localtime(timestamp))
            ),
            -1,
        )
        self.assertNotEqual(
            str(probe_req).find(
                "aa:bb:cc:dd:ee:ff (Unknown OUI) -> Test ESSID"
            ),
            -1
        )

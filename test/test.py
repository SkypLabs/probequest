"""
Unit tests written with the 'unittest' module.
"""

# pylint: disable=import-error
# pylint: disable=unused-variable

import unittest
import pylint.lint
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.packet import fuzz
from netaddr.core import AddrFormatError
from probequest.config import Config
from probequest.probe_request import ProbeRequest
from probequest.probe_request_sniffer import ProbeRequestSniffer


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
            probe_req = ProbeRequest()  # noqa: F841

    def test_with_only_one_parameter(self):
        """
        Initialises a 'ProbeRequest' object with only one parameter.
        """

        # pylint: disable=no-value-for-parameter

        timestamp = 1517872027.0

        with self.assertRaises(TypeError):
            probe_req = ProbeRequest(timestamp)  # noqa: F841

    def test_with_only_two_parameters(self):
        """
        Initialises a 'ProbeRequest' object with only two parameters.
        """

        # pylint: disable=no-value-for-parameter

        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee:ff"

        with self.assertRaises(TypeError):
            probe_req = ProbeRequest(timestamp, s_mac)  # noqa: F841

    def test_create_a_probe_request(self):
        """
        Creates a new 'ProbeRequest' with all the required parameters.
        """

        # pylint: disable=no-self-use

        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee:ff"
        essid = "Test ESSID"

        probe_req = ProbeRequest(timestamp, s_mac, essid)  # noqa: F841

    def test_bad_mac_address(self):
        """
        Initialises a 'ProbeRequest' object with a malformed MAC address.
        """

        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee"
        essid = "Test ESSID"

        with self.assertRaises(AddrFormatError):
            probe_req = ProbeRequest(timestamp, s_mac, essid)  # noqa: F841

    def test_print_a_probe_request(self):
        """
        Initialises a 'ProbeRequest' object and prints it.
        """

        timestamp = 1517872027.0
        s_mac = "aa:bb:cc:dd:ee:ff"
        essid = "Test ESSID"

        probe_req = ProbeRequest(timestamp, s_mac, essid)

        self.assertNotEqual(
            str(probe_req).find("Mon, 05 Feb 2018 23:07:07"),
            -1
        )
        self.assertNotEqual(
            str(probe_req).find("aa:bb:cc:dd:ee:ff (None) -> Test ESSID"),
            -1
        )


class TestConfig(unittest.TestCase):
    """
    Unit tests for the 'Config' class.
    """

    def test_bad_display_function(self):
        """
        Assigns a non-callable object to the display callback function.
        """

        with self.assertRaises(TypeError):
            config = Config()
            config.display_func = "test"

    def test_bad_storage_function(self):
        """
        Assigns a non-callable object to the storage callback function.
        """

        with self.assertRaises(TypeError):
            config = Config()
            config.storage_func = "test"


class TestProbeRequestSniffer(unittest.TestCase):
    """
    Unit tests for the 'ProbeRequestSniffer' class.
    """

    def test_without_parameters(self):
        """
        Initialises a 'ProbeRequestSniffer' object without parameters.
        """

        # pylint: disable=no-value-for-parameter

        with self.assertRaises(TypeError):
            sniffer = ProbeRequestSniffer()  # noqa: F841

    def test_bad_parameter(self):
        """
        Initialises a 'ProbeRequestSniffer' object with a bad parameter.
        """

        # pylint: disable=no-value-for-parameter

        with self.assertRaises(AttributeError):
            sniffer = ProbeRequestSniffer("test")  # noqa: F841

    def test_create_sniffer(self):
        """
        Creates a 'ProbeRequestSniffer' object with the correct parameter.
        """

        # pylint: disable=no-self-use

        config = Config()
        sniffer = ProbeRequestSniffer(config)  # noqa: F841

    def test_stop_before_start(self):
        """
        Creates a 'ProbeRequestSniffer' object and stops the sniffer before
        starting it.
        """

        # pylint: disable=no-self-use

        config = Config()
        sniffer = ProbeRequestSniffer(config)
        sniffer.stop()


class TestProbeRequestParser(unittest.TestCase):
    """
    Unit tests for the 'ProbeRequestParser' class.
    """

    def test_no_probe_request_layer(self):
        """
        Creates a non-probe-request Wi-Fi packet and parses it with the
        'ProbeRequestParser.parse()' function.
        """

        # pylint: disable=no-self-use

        packet = RadioTap() \
            / Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="aa:bb:cc:11:22:33",
                addr3="dd:ee:ff:11:22:33"
            )

        ProbeRequestSniffer.ProbeRequestParser.parse(packet)

    def test_empty_essid(self):
        """
        Creates a probe request packet with an empty ESSID field and parses
        it with the 'ProbeRequestParser.parse()' function.
        """

        # pylint: disable=no-self-use

        packet = RadioTap() \
            / Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="aa:bb:cc:11:22:33",
                addr3="dd:ee:ff:11:22:33"
            ) \
            / Dot11ProbeReq() \
            / Dot11Elt(
                info=""
            )

        ProbeRequestSniffer.ProbeRequestParser.parse(packet)

    def test_fuzz_packets(self):
        """
        Parses 1000 randomly-generated probe requests with the
        'ProbeRequestParser.parse()' function.
        """

        # pylint: disable=no-self-use

        for i in range(0, 1000):
            packet = RadioTap()/fuzz(Dot11()/Dot11ProbeReq()/Dot11Elt())
            ProbeRequestSniffer.ProbeRequestParser.parse(packet)


class TestLinter(unittest.TestCase):
    """
    Unit tests for Python linters.
    """

    # Some linting errors will be fixed while
    # refactoring the code.
    @unittest.expectedFailure
    def test_pylint(self):
        """
        Executes Pylint.
        """

        # pylint: disable=no-self-use

        pylint.lint.Run([
            "probequest",
            "test"
        ])

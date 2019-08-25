"""
Unit tests written with the 'unittest' module.
"""

# pylint: disable=import-error
# pylint: disable=unused-variable

from queue import Queue
import unittest
import pylint.lint
from netaddr.core import AddrFormatError

from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.packet import fuzz
from scapy.error import Scapy_Exception

from probequest.config import Config
from probequest.probe_request import ProbeRequest
from probequest.probe_request_sniffer import ProbeRequestSniffer
from probequest.packet_sniffer import PacketSniffer
from probequest.fake_packet_sniffer import FakePacketSniffer
from probequest.probe_request_parser import ProbeRequestParser


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

    def test_default_frame_filter(self):
        """
        Tests the default frame filter.
        """

        config = Config()
        frame_filter = config.generate_frame_filter()

        self.assertEqual(
            frame_filter,
            "type mgt subtype probe-req"
        )

    def test_frame_filter_with_mac_filtering(self):
        """
        Tests the frame filter when some MAC addresses need to be filtered.
        """

        config = Config()
        config.mac_filters = ["a4:77:33:9a:73:5c", "b0:05:94:5d:5a:4d"]
        frame_filter = config.generate_frame_filter()

        self.assertEqual(
            frame_filter,
            "type mgt subtype probe-req" +
            " and (ether src host a4:77:33:9a:73:5c" +
            "|| ether src host b0:05:94:5d:5a:4d)"
        )

    def test_frame_filter_with_mac_exclusion(self):
        """
        Tests the frame filter when some MAC addresses need to be excluded.
        """

        config = Config()
        config.mac_exclusions = ["a4:77:33:9a:73:5c", "b0:05:94:5d:5a:4d"]
        frame_filter = config.generate_frame_filter()

        self.assertEqual(
            frame_filter,
            "type mgt subtype probe-req" +
            " and not (ether src host a4:77:33:9a:73:5c" +
            "|| ether src host b0:05:94:5d:5a:4d)"
        )

    def test_compile_essid_regex_with_an_empty_regex(self):
        """
        Tests 'complile_essid_regex' with an empty regex.
        """

        config = Config()
        compiled_regex = config.complile_essid_regex()

        self.assertEqual(compiled_regex, None)

    def test_compile_essid_regex_with_a_case_sensitive_regex(self):
        """
        Tests 'complile_essid_regex' with a case-sensitive regex.
        """

        from re import compile as rcompile

        config = Config()
        config.essid_regex = "Free Wi-Fi"
        compiled_regex = config.complile_essid_regex()

        self.assertEqual(compiled_regex, rcompile(config.essid_regex))

    def test_compile_essid_regex_with_a_case_insensitive_regex(self):
        """
        Tests 'complile_essid_regex' with a case-insensitive regex.
        """

        from re import compile as rcompile, IGNORECASE

        config = Config()
        config.essid_regex = "Free Wi-Fi"
        config.ignore_case = True
        compiled_regex = config.complile_essid_regex()

        self.assertEqual(compiled_regex, rcompile(
            config.essid_regex, IGNORECASE))


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


class TestPacketSniffer(unittest.TestCase):
    """
    Unit tests for the 'PacketSniffer' class.
    """

    def test_new_packet(self):
        """
        Tests the 'new_packet' method.
        """

        config = Config()
        new_packets = Queue()
        sniffer = PacketSniffer(config, new_packets)

        self.assertEqual(sniffer.new_packets.qsize(), 0)

        packet = RadioTap() \
            / Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="aa:bb:cc:11:22:33",
                addr3="dd:ee:ff:11:22:33"
            ) \
            / Dot11ProbeReq() \
            / Dot11Elt(
                info="Test"
            )

        sniffer.new_packet(packet)
        self.assertEqual(sniffer.new_packets.qsize(), 1)

        ProbeRequestParser.parse(sniffer.new_packets.get(timeout=1))

    def test_stop_before_start(self):
        """
        Creates a 'PacketSniffer' object and stops the sniffer before starting
        it.
        """

        config = Config()
        new_packets = Queue()
        sniffer = PacketSniffer(config, new_packets)

        with self.assertRaises(Scapy_Exception):
            sniffer.stop()

    def test_is_running_before_start(self):
        """
        Creates a 'PacketSniffer' object and runs 'is_running' before starting
        the sniffer.
        """

        config = Config()
        new_packets = Queue()
        sniffer = PacketSniffer(config, new_packets)

        self.assertFalse(sniffer.is_running())


class TestFakePacketSniffer(unittest.TestCase):
    """
    Unit tests for the 'FakePacketSniffer' class.
    """

    def test_new_packet(self):
        """
        Tests the 'new_packet' method.
        """

        config = Config()
        new_packets = Queue()
        sniffer = FakePacketSniffer(config, new_packets)

        self.assertEqual(sniffer.new_packets.qsize(), 0)

        sniffer.new_packet()
        self.assertEqual(sniffer.new_packets.qsize(), 1)
        sniffer.new_packet()
        self.assertEqual(sniffer.new_packets.qsize(), 2)
        sniffer.new_packet()
        self.assertEqual(sniffer.new_packets.qsize(), 3)

        ProbeRequestParser.parse(sniffer.new_packets.get(timeout=1))
        ProbeRequestParser.parse(sniffer.new_packets.get(timeout=1))
        ProbeRequestParser.parse(sniffer.new_packets.get(timeout=1))

    def test_stop_before_start(self):
        """
        Creates a 'FakePacketSniffer' object and stops the sniffer before
        starting it.
        """

        config = Config()
        new_packets = Queue()
        sniffer = FakePacketSniffer(config, new_packets)

        with self.assertRaises(RuntimeError):
            sniffer.stop()

    def test_stop_before_start_using_join(self):
        """
        Creates a 'FakePacketSniffer' object and stops the sniffer before
        starting it.
        """

        config = Config()
        new_packets = Queue()
        sniffer = FakePacketSniffer(config, new_packets)

        with self.assertRaises(RuntimeError):
            sniffer.join()


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

        ProbeRequestParser.parse(packet)

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

        ProbeRequestParser.parse(packet)

    def test_fuzz_packets(self):
        """
        Parses 1000 randomly-generated probe requests with the
        'ProbeRequestParser.parse()' function.
        """

        # pylint: disable=no-self-use

        for i in range(0, 1000):
            packet = RadioTap()/fuzz(Dot11()/Dot11ProbeReq()/Dot11Elt())
            ProbeRequestParser.parse(packet)


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

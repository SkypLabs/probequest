"""
Unit tests for the packet sniffer module.
"""

import unittest
from queue import Queue

from scapy.error import Scapy_Exception
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt

from probequest.config import Config
from probequest.packet_sniffer import PacketSniffer
from probequest.probe_request_parser import ProbeRequestParser


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

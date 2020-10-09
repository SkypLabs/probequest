"""
Unit tests for the packet sniffer module.
"""

import logging
import unittest
from queue import Queue

from scapy.error import Scapy_Exception
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt

from probequest.packet_sniffer import PacketSniffer
from probequest.probe_request_parser import ProbeRequestParser

from .utils import create_fake_config


class TestPacketSniffer(unittest.TestCase):
    """
    Unit tests for the 'PacketSniffer' class.
    """

    def setUp(self):
        """
        Creates a fake package logger.
        """

        self.logger = logging.getLogger("probequest")
        self.logger.setLevel(logging.DEBUG)

    def test_new_packet(self):
        """
        Tests the 'new_packet' method.
        """

        new_packets = Queue()
        config = create_fake_config()
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

        config = create_fake_config()
        new_packets = Queue()
        sniffer = PacketSniffer(config, new_packets)

        with self.assertLogs(self.logger, level=logging.DEBUG):
            with self.assertRaises(Scapy_Exception):
                sniffer.stop()

    def test_is_running_before_start(self):
        """
        Creates a 'PacketSniffer' object and runs 'is_running' before starting
        the sniffer.
        """

        config = create_fake_config()
        new_packets = Queue()
        sniffer = PacketSniffer(config, new_packets)

        self.assertFalse(sniffer.is_running())

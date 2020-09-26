"""
Unit tests for the fake packet sniffer module.
"""

import unittest
from queue import Queue

from probequest.config import Config
from probequest.fake_packet_sniffer import FakePacketSniffer
from probequest.probe_request_parser import ProbeRequestParser


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

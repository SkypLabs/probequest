"""
Unit tests for the fake packet sniffer module.
"""

import logging
import unittest
from queue import Queue

from probequest.fake_packet_sniffer import FakePacketSniffer
from probequest.probe_request_parser import ProbeRequestParser

from .utils import create_fake_config


class TestFakePacketSniffer(unittest.TestCase):
    """
    Unit tests for the 'FakePacketSniffer' class.
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

        config = create_fake_config()
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

        config = create_fake_config()
        new_packets = Queue()
        sniffer = FakePacketSniffer(config, new_packets)

        with self.assertLogs(self.logger, level=logging.DEBUG):
            with self.assertRaises(RuntimeError):
                sniffer.stop()

    def test_stop_before_start_using_join(self):
        """
        Creates a 'FakePacketSniffer' object and stops the sniffer before
        starting it.
        """

        config = create_fake_config()
        new_packets = Queue()
        sniffer = FakePacketSniffer(config, new_packets)

        with self.assertLogs(self.logger, level=logging.DEBUG):
            with self.assertRaises(RuntimeError):
                sniffer.join()

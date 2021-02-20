"""
Unit tests for the probe request parser module.
"""

import unittest

from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.packet import fuzz

from probequest.probe_request_parser import ProbeRequestParser


class TestProbeRequestParser(unittest.TestCase):
    """
    Unit tests for the 'ProbeRequestParser' class.
    """

    dot11_layer = Dot11(
        addr1="ff:ff:ff:ff:ff:ff",
        addr2="aa:bb:cc:11:22:33",
        addr3="dd:ee:ff:11:22:33",
    )

    def test_no_probe_request_layer(self):
        """
        Creates a non-probe-request Wi-Fi packet and parses it with the
        'ProbeRequestParser.parse()' function.
        """

        with self.assertRaises(TypeError):
            packet = RadioTap() / self.dot11_layer
            ProbeRequestParser.parse(packet)

    def test_empty_essid(self):
        """
        Creates a probe request packet with an empty ESSID field and parses
        it with the 'ProbeRequestParser.parse()' function.
        """

        packet = RadioTap() \
            / self.dot11_layer \
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

        with self.assertRaises(TypeError):
            for _ in range(0, 1000):
                packet = RadioTap()/fuzz(Dot11()/Dot11ProbeReq()/Dot11Elt())
                ProbeRequestParser.parse(packet)

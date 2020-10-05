"""
Wi-Fi probe request sniffer.
"""

import logging
from queue import Queue

from scapy.arch import get_if_hwaddr
from scapy.error import Scapy_Exception

from .packet_sniffer import PacketSniffer
from .fake_packet_sniffer import FakePacketSniffer
from .probe_request_parser import ProbeRequestParser


class ProbeRequestSniffer:
    """
    Wi-Fi probe request sniffer.

    It is composed of a packet sniffer and a packet parser, both running
    in a thread and intercommunicating using a queue.
    """

    def __init__(self, config):
        self.logger = logging.getLogger(__name__)

        self.config = config

        self.new_packets = Queue()
        self.new_sniffer()
        self.new_parser()

    def start(self):
        """
        Starts the probe request sniffer.

        This method will start the sniffing and parsing threads.
        """

        self.logger.debug("Starting the probe request sniffer")

        try:
            # Test if the interface exists.
            get_if_hwaddr(self.config.interface)
        except Scapy_Exception:
            pass

        self.sniffer.start()

        try:
            self.parser.start()
        except RuntimeError:
            self.new_parser()
            self.parser.start()

    def stop(self):
        """
        Stops the probe request sniffer.

        This method will stop the sniffing and parsing threads.
        """

        self.logger.debug("Stopping the probe request sniffer")

        try:
            self.sniffer.stop()
        except Scapy_Exception:
            # The sniffer was not running.
            pass

        try:
            self.parser.join()
        except RuntimeError:
            # stop() has been called before start().
            pass

    def new_sniffer(self):
        """
        Creates a new sniffing thread.

        If the '--fake' option is set, a fake packet sniffer will be used.
        """

        if self.config.fake:
            self.logger.debug("Creating a new fake probe request sniffer")
            self.sniffer = FakePacketSniffer(
                self.config,
                self.new_packets
            )
        else:
            self.logger.debug("Creating a new probe request sniffer")
            self.sniffer = PacketSniffer(
                self.config,
                self.new_packets
            )

    def new_parser(self):
        """
        Creates a new parsing thread.
        """

        self.logger.debug("Creating a new probe request parser")

        self.parser = ProbeRequestParser(
            self.config,
            self.new_packets
        )

    def is_running(self):
        """
        Returns true if the probe request sniffer is running and false
        otherwise.
        """

        return self.sniffer.is_running()

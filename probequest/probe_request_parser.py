"""
Probe request parser module.
"""

import logging
from queue import Empty
from re import match
from threading import Thread, Event

from scapy.layers.dot11 import RadioTap, Dot11ProbeReq

from .probe_request import ProbeRequest


class ProbeRequestParser(Thread):
    """
    A Wi-Fi probe request parsing thread.
    """

    def __init__(self, config, new_packets):
        super().__init__()

        self.logger = logging.getLogger(__name__)

        self.config = config
        self.new_packets = new_packets

        self.cregex = self.config.complile_essid_regex()

        self.stop_parser = Event()

    def run(self):
        self.logger.debug("Starting the probe request parser")

        # The parser continues to do its job even after the call of the
        # join method if the queue is not empty.
        while not self.stop_parser.isSet() or not self.new_packets.empty():
            try:
                packet = self.new_packets.get(timeout=1)
                probe_request = self.parse(packet)

                if probe_request is None:
                    continue

                if not probe_request.essid:
                    continue

                if (self.config.essid_filters is not None
                        and probe_request.essid
                        not in self.config.essid_filters):
                    continue

                if (self.cregex is not None
                        and not
                        match(self.cregex, probe_request.essid)):
                    continue

                self.config.display_func(probe_request)
                self.config.storage_func(probe_request)

                self.new_packets.task_done()
            except Empty:
                pass

    def join(self, timeout=None):
        """
        Stops the probe request parsing thread.
        """

        self.logger.debug("Stopping the probe request parser")

        self.stop_parser.set()
        super().join(timeout)

    @staticmethod
    def parse(packet):
        """
        Parses the raw packet and returns a probe request object.
        """

        try:
            if packet.haslayer(Dot11ProbeReq):
                timestamp = packet.getlayer(RadioTap).time
                s_mac = packet.getlayer(RadioTap).addr2
                essid = packet.getlayer(Dot11ProbeReq).info.decode("utf-8")

                return ProbeRequest(timestamp, s_mac, essid)

            return None
        except UnicodeDecodeError:
            # The ESSID is not a valid UTF-8 string.
            return None

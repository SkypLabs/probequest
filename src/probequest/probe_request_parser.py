"""
Probe request parser module.
"""

import logging

from scapy.pipetool import Drain
from scapy.layers.dot11 import RadioTap, Dot11ProbeReq

from probequest.probe_request import ProbeRequest


class ProbeRequestParser(Drain):
    """
    A Wi-Fi probe request parsing drain.
    """

    def __init__(self, config, name=None):
        self.logger = logging.getLogger(__name__)

        Drain.__init__(self, name=name)

        self.config = config

        self.logger.info("Probe request parser initialised")

    def push(self, msg):
        try:
            self._send(self.parse(msg))
        except TypeError:
            return

    def high_push(self, msg):
        try:
            self._high_send(self.parse(msg))
        except TypeError:
            return

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

            # The packet is not a probe request.
            raise TypeError
        except UnicodeDecodeError as unicode_decode_err:
            # The ESSID is not a valid UTF-8 string.
            raise TypeError from unicode_decode_err

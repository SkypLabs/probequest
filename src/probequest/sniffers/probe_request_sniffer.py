"""
Probe request sniffer module.
"""

import logging

from scapy.scapypipes import SniffSource


class ProbeRequestSniffer(SniffSource):
    """
    Probe request sniffer.

    Wrapper around the 'SniffSource' Scapy pipe module.
    """

    def __init__(self, config):
        self.logger = logging.getLogger(__name__)

        self.config = config

        frame_filter = self.config.frame_filter

        SniffSource.__init__(
            self,
            iface=self.config.interface,
            filter=frame_filter
        )

        self.logger.info("Probe request sniffer initialised")

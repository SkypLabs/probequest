"""
Probe request console module.
"""

import logging

from scapy.pipetool import Sink


class ProbeRequestConsole(Sink):
    """
    Probe request displaying sink.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        Sink.__init__(self)

        self.logger.info("Console initialised")

    def push(self, msg):
        print(msg)

    def high_push(self, msg):
        print(msg)

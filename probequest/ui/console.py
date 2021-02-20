"""
Probe request console module.
"""

from scapy.pipetool import Sink


class ProbeRequestConsole(Sink):
    """
    Probe request displaying sink.
    """

    def push(self, msg):
        print(msg)

    def high_push(self, msg):
        print(msg)

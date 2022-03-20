"""
Probe request filter module.
"""

import logging
from re import match

from scapy.pipetool import Drain


class ProbeRequestFilter(Drain):
    """
    A Wi-Fi probe request filtering drain.
    """

    def __init__(self, config, name=None):
        self.logger = logging.getLogger(__name__)

        Drain.__init__(self, name=name)

        self._config = config
        self._cregex = self._config.compiled_essid_regex

        self.logger.info("Probe request filter initialised")

    def push(self, msg):
        if self.can_pass(msg):
            self._send(msg)

    def high_push(self, msg):
        if self.can_pass(msg):
            self._send(msg)

    def can_pass(self, probe_req):
        """
        Whether or not the probe request given as parameter can pass the drain
        according to a set of filters.
        """

        # If the probe request doesn't have an ESSID.
        if not probe_req.essid:
            return False

        # If the probe request's ESSID is not one of those in the filtering
        # list.
        if (self._config.essid_filters is not None and
                probe_req.essid not in self._config.essid_filters):
            return False

        # If the probe request's ESSID doesn't match the regex.
        if (self._cregex is not None and
                not match(self._cregex, probe_req.essid)):
            return False

        return True

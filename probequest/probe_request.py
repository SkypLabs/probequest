"""
A Wi-Fi probe request.
"""

from time import localtime, strftime
from netaddr import EUI, NotRegisteredError


class ProbeRequest:
    """
    Probe request class.
    """

    def __init__(self, timestamp, s_mac, essid):
        self.timestamp = timestamp
        self.s_mac = str(s_mac)
        self.essid = str(essid)

        self._s_mac_oui = None

    def __str__(self):
        timestamp = strftime(
                "%a, %d %b %Y %H:%M:%S %Z",
                localtime(self.timestamp)
                )
        s_mac = self.s_mac
        s_mac_oui = self.s_mac_oui
        essid = self.essid

        return f"{timestamp} - {s_mac} ({s_mac_oui}) -> {essid}"

    @property
    def s_mac_oui(self):
        """
        OUI of the station's MAC address as a string.

        The value is cached once computed.
        """

        # pylint: disable=no-member

        if self._s_mac_oui is None:
            try:
                self._s_mac_oui = EUI(self.s_mac).oui.registration().org
            except NotRegisteredError:
                self._s_mac_oui = "Unknown OUI"

        return self._s_mac_oui

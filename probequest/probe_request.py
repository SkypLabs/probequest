from netaddr import EUI, NotRegisteredError
from time import localtime, strftime

class ProbeRequest:
    """
    A Wi-Fi probe request.
    """

    def __init__(self, timestamp, s_mac, essid):
        self.timestamp = timestamp
        self.s_mac = s_mac
        self.essid = essid

        self.s_mac_oui = self.get_mac_organisation()

    def __str__(self):
        return "{timestamp} - {s_mac} ({mac_org}) -> {essid}".format(
            timestamp=strftime("%a, %d %b %Y %H:%M:%S %Z", localtime(self.timestamp)),
            s_mac=self.s_mac,
            mac_org=self.s_mac_oui,
            essid=self.essid
        )

    def get_mac_organisation(self):
        """
        Returns the OUI of the MAC address as a string.
        """

        try:
            return EUI(self.s_mac).oui.registration().org
        except NotRegisteredError:
            return None

"""
Fake packet sniffer module.
"""

from threading import Thread, Event

from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt

from faker import Faker
from faker_wifi_essid import WifiESSID


class FakePacketSniffer(Thread):
    """
    A fake packet sniffing thread.

    This thread returns fake Wi-Fi ESSIDs for development and test purposes.
    """

    def __init__(self, config, new_packets):
        super().__init__()

        self.config = config
        self.new_packets = new_packets

        self.stop_sniffer = Event()

        self.fake = Faker()
        self.fake.add_provider(WifiESSID)

    def run(self):
        from time import sleep

        while not self.stop_sniffer.isSet():
            sleep(1)
            self.new_packet()

    def join(self, timeout=None):
        """
        Stops the fake packet sniffer.
        """

        self.stop_sniffer.set()
        super().join(timeout)

    def stop(self):
        """
        Stops the fake packet sniffer.

        Alias for 'join()'.
        """

        self.join()

    def new_packet(self):
        """
        Adds a new fake packet to the queue to be processed.
        """

        # pylint: disable=no-member

        fake_probe_req = RadioTap() \
            / Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self.fake.mac_address(),
                addr3=self.fake.mac_address()
            ) \
            / Dot11ProbeReq() \
            / Dot11Elt(
                info=self.fake.wifi_essid()
            )

        self.new_packets.put(fake_probe_req)

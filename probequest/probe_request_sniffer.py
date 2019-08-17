"""
A Wi-Fi probe request sniffer.
"""

from queue import Queue, Empty
from re import match
from threading import Thread, Event

from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.sendrecv import AsyncSniffer
from scapy.error import Scapy_Exception

from probequest.probe_request import ProbeRequest


class ProbeRequestSniffer:
    """
    Probe request sniffer class.
    """

    def __init__(self, config):
        self.config = config

        self.new_packets = Queue()
        self.new_sniffer()
        self.new_parser()

    def start(self):
        """
        Starts the probe request sniffer.

        This method will start the sniffing and parsing threads.
        """

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
        """

        if self.config.fake:
            self.sniffer = self.FakePacketSniffer(
                self.config,
                self.new_packets
            )
        else:
            self.sniffer = AsyncSniffer(
                iface=self.config.interface,
                filter=self.config.generate_frame_filter(),
                store=False,
                prn=self.new_packet
            )

    def new_parser(self):
        """
        Creates a new parsing thread.
        """

        self.parser = self.ProbeRequestParser(
            self.config,
            self.new_packets
        )

    def is_running(self):
        """
        Returns true if the probe request sniffer is running and
        false otherwise.
        """

        return self.sniffer.running

    def new_packet(self, packet):
        """
        Adds a new packet to the queue to be processed.
        """

        self.new_packets.put(packet)

    class FakePacketSniffer(Thread):
        """
        A fake packet sniffing thread.

        This thread returns fake Wi-Fi ESSIDs for development
        and test purposes.
        """

        def __init__(self, config, new_packets):
            super().__init__()

            self.config = config
            self.new_packets = new_packets

            self.stop_sniffer = Event()
            self.exception = None

            from faker import Faker
            from faker_wifi_essid import WifiESSID

            self.fake = Faker()
            self.fake.add_provider(WifiESSID)

        def run(self):
            from time import sleep

            try:
                while not self.stop_sniffer.isSet():
                    sleep(1)
                    self.new_packet()
            # pylint: disable=broad-except
            except Exception as exception:
                self.exception = exception

                if self.config.debug:
                    print("[!] Exception: " + str(exception))

        def join(self, timeout=None):
            """
            Stops the fake packet sniffer.
            """

            self.stop_sniffer.set()
            super().join(timeout)

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

        def should_stop_sniffer(self, packet):
            """
            Returns true if the fake sniffer should be stopped
            and false otherwise.
            """

            # pylint: disable=unused-argument

            return self.stop_sniffer.isSet()

        def get_exception(self):
            """
            Returns the raised exception if any, otherwise returns none.
            """
            return self.exception

    class ProbeRequestParser(Thread):
        """
        A Wi-Fi probe request parsing thread.
        """

        def __init__(self, config, new_packets):
            super().__init__()

            self.config = config
            self.new_packets = new_packets

            self.cregex = self.config.complile_essid_regex()

            self.stop_parser = Event()

            if self.config.debug:
                print("[!] ESSID filters: " + str(self.config.essid_filters))
                print("[!] ESSID regex: " + str(self.config.essid_regex))
                print("[!] Ignore case: " + str(self.config.ignore_case))

        def run(self):
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

"""
A Wi-Fi probe request sniffer.
"""

from queue import Queue, Empty
from re import compile as rcompile, match, IGNORECASE
from threading import Thread, Event

from scapy.config import conf
from scapy.data import ETH_P_ALL
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.sendrecv import sniff

from probequest.probe_request import ProbeRequest

class ProbeRequestSniffer:
    """
    Probe request sniffer class.
    """

    SNIFFER_STOP_TIMEOUT = 2.0

    def __init__(self, interface, **kwargs):
        self.interface = interface
        self.essid_filters = kwargs.get("essid", None)
        self.essid_regex = kwargs.get("regex", None)
        self.ignore_case = kwargs.get("ignore_case", None)
        self.mac_exclusions = kwargs.get("exclude", None)
        self.mac_filters = kwargs.get("station", None)
        self.display_func = kwargs.get("display_func", lambda p: None)
        self.storage_func = kwargs.get("storage_func", lambda p: None)
        self.fake = kwargs.get("fake", False)
        self.debug = kwargs.get("debug", False)

        if not hasattr(self.display_func, "__call__"):
            raise TypeError("The display function parameter is not a callable object")
        if not hasattr(self.storage_func, "__call__"):
            raise TypeError("The storage function parameter is not a callable object")

        self.new_packets = Queue()
        self.new_sniffer()
        self.new_parser()

        self.sniffer_running = False

    def start(self):
        """
        Starts the probe request sniffer.

        This method will start the sniffing and parsing threads.
        """

        try:
            self.sniffer.start()
        except RuntimeError:
            self.new_sniffer()
            self.sniffer.start()

        try:
            self.parser.start()
        except RuntimeError:
            self.new_parser()
            self.parser.start()

        e = self.sniffer.get_exception()

        if e is not None:
            raise e

        self.sniffer_running = True

    def stop(self):
        """
        Stops the probe request sniffer.

        This method will stop the sniffing and parsing threads.
        """

        try:
            self.sniffer.join(timeout=ProbeRequestSniffer.SNIFFER_STOP_TIMEOUT)
        except RuntimeError:
            # stop() has been called before start().
            pass
        finally:
            if self.sniffer.isAlive():
                self.sniffer.socket.close()

        try:
            self.parser.join()
        except RuntimeError:
            # stop() has been called before start().
            pass

        self.sniffer_running = False

    def new_sniffer(self):
        """
        Creates a new sniffing thread.
        """

        if self.fake:
            self.sniffer = self.FakePacketSniffer(
                self.new_packets,
                debug=self.debug
            )
        else:
            self.sniffer = self.PacketSniffer(
                self.interface,
                self.new_packets,
                mac_exclusions=self.mac_exclusions,
                mac_filters=self.mac_filters,
                debug=self.debug
            )

    def new_parser(self):
        """
        Creates a new parsing thread.
        """

        self.parser = self.ProbeRequestParser(
            self.new_packets,
            essid_filters=self.essid_filters,
            essid_regex=self.essid_regex,
            ignore_case=self.ignore_case,
            display_func=self.display_func,
            storage_func=self.storage_func,
            debug=self.debug
        )

    def is_running(self):
        """
        Returns true if the probe request sniffer is running and
        false otherwise.
        """

        return self.sniffer_running

    class PacketSniffer(Thread):
        """
        A packet sniffing thread.
        """

        def __init__(self, interface, new_packets, **kwargs):
            super().__init__()

            self.daemon = True

            self.interface = interface
            self.new_packets = new_packets

            self.mac_exclusions = kwargs.get("mac_exclusions", None)
            self.mac_filters = kwargs.get("mac_filters", None)
            self.debug = kwargs.get("debug", False)

            self.frame_filters = "type mgt subtype probe-req"
            self.socket = None
            self.stop_sniffer = Event()

            self.exception = None

            if self.mac_exclusions is not None:
                self.frame_filters += " and not ("

                for i, station in enumerate(self.mac_exclusions):
                    if i == 0:
                        self.frame_filters += "ether src host {s_mac}".format(s_mac=station)
                    else:
                        self.frame_filters += " || ether src host {s_mac}".format(s_mac=station)

                self.frame_filters += ")"

            if self.mac_filters is not None:
                self.frame_filters += " and ("

                for i, station in enumerate(self.mac_filters):
                    if i == 0:
                        self.frame_filters += "ether src host {s_mac}".format(s_mac=station)
                    else:
                        self.frame_filters += " || ether src host {s_mac}".format(s_mac=station)

                self.frame_filters += ")"

            if self.debug:
                print("[!] Frame filters: " + self.frame_filters)

        def run(self):
            try:
                self.socket = conf.L2listen(
                    type=ETH_P_ALL,
                    iface=self.interface,
                    filter=self.frame_filters
                )

                sniff(
                    opened_socket=self.socket,
                    store=False,
                    prn=self.new_packet,
                    stop_filter=self.should_stop_sniffer
                )
            except Exception as e:
                self.exception = e

                if self.debug:
                    print("[!] Exception: " + str(e))

        def join(self, timeout=None):
            """
            Stops the packet sniffer.
            """

            self.stop_sniffer.set()
            super().join(timeout)

        def new_packet(self, packet):
            """
            Adds a new packet to the queue to be processed.
            """

            self.new_packets.put(packet)

        def should_stop_sniffer(self):
            """
            Returns true if the sniffer should be stopped and false otherwise.
            """

            return self.stop_sniffer.isSet()

        def get_exception(self):
            """
            Returns the raised exception if any, otherwise returns none.
            """
            return self.exception

    class FakePacketSniffer(Thread):
        """
        A fake packet sniffing thread.

        This thread returns fake Wi-Fi ESSIDs for development
        and test purposes.
        """


        def __init__(self, new_packets, **kwargs):
            super().__init__()

            self.new_packets = new_packets
            self.stop_sniffer = Event()
            self.exception = None

            self.debug = kwargs.get("debug", False)

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
            except Exception as e:
                self.exception = e

                if self.debug:
                    print("[!] Exception: " + str(e))

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

        def should_stop_sniffer(self):
            """
            Returns true if the fake sniffer should be stopped and false otherwise.
            """

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

        def __init__(self, new_packets, **kwargs):
            super().__init__()

            self.new_packets = new_packets
            self.essid_filters = kwargs.get("essid_filters", None)
            self.essid_regex = kwargs.get("essid_regex", None)
            self.ignore_case = kwargs.get("ignore_case", False)
            self.display_func = kwargs.get("display_func", lambda p: None)
            self.storage_func = kwargs.get("storage_func", lambda p: None)
            self.debug = kwargs.get("debug", False)

            self.stop_parser = Event()

            if self.debug:
                print("[!] ESSID filters: " + str(self.essid_filters))
                print("[!] ESSID regex: " + str(self.essid_regex))
                print("[!] Ignore case: " + str(self.ignore_case))

            if self.essid_regex is not None:
                if self.ignore_case:
                    self.essid_regex = rcompile(self.essid_regex, IGNORECASE)
                else:
                    self.essid_regex = rcompile(self.essid_regex)
            else:
                self.essid_regex = None

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

                    if (self.essid_filters is not None
                            and not probe_request.essid in self.essid_filters):
                        continue

                    if (self.essid_regex is not None
                            and not match(self.essid_regex, probe_request.essid)):
                        continue

                    self.display_func(probe_request)
                    self.storage_func(probe_request)

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

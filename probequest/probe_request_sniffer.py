from queue import Queue, Empty
from re import compile as rcompile, match, IGNORECASE
from scapy.all import *
from threading import Thread, Event

from probequest.probe_request import ProbeRequest

class ProbeRequestSniffer:
    """
    A Wi-Fi probe request sniffer.
    """

    SNIFFER_STOP_TIMEOUT = 2.0

    def __init__(self, interface, essid_filters=None, essid_regex=None, ignore_case=False, mac_exclusions=None, mac_filters=None, display_func=lambda p: None, storage_func=lambda p: None, debug=False):
        if not hasattr(display_func, "__call__"):
            raise TypeError("The display function parameter is not a callable object")
        if not hasattr(storage_func, "__call__"):
            raise TypeError("The storage function parameter is not a callable object")

        self.new_packets = Queue()

        self.interface = interface
        self.essid_filters = essid_filters
        self.essid_regex = essid_regex
        self.ignore_case = ignore_case
        self.mac_exclusions = mac_exclusions
        self.mac_filters = mac_filters
        self.display_func = display_func
        self.storage_func = storage_func
        self.debug = debug

        self.new_sniffer()
        self.new_parser()

        self.sniffer_running = False

    def start(self):
        """
        Starts the probe request sniffer.

        This method will start the sniffing thread and the parsing thread.
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

        This method will stop the sniffing thread and the parsing thread.
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

        self.sniffer = self.PacketSniffer(
            self.new_packets,
            self.interface,
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

        def __init__(self, new_packets, interface, mac_exclusions=None, mac_filters=None, debug=False):
            super().__init__()

            self.daemon = True

            self.new_packets = new_packets
            self.interface = interface

            self.frame_filters = "type mgt subtype probe-req"
            self.socket = None
            self.stop_sniffer = Event()

            self.exception = None
            self.debug = debug

            if mac_exclusions is not None:
                self.frame_filters += " and not ("

                for i, station in enumerate(mac_exclusions):
                    if i == 0:
                        self.frame_filters += "ether src host {s_mac}".format(s_mac=station)
                    else:
                        self.frame_filters += " || ether src host {s_mac}".format(s_mac=station)

                self.frame_filters += ")"

            if mac_filters is not None:
                self.frame_filters += " and ("

                for i, station in enumerate(mac_filters):
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

        def should_stop_sniffer(self, packet):
            """
            Returns true if the sniffer should be stopped and false otherwise.
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

        def __init__(self, new_packets, essid_filters=None, essid_regex=None, ignore_case=False, display_func=lambda p: None, storage_func=lambda p: None, debug=False):
            super().__init__()

            self.new_packets = new_packets
            self.essid_filters = essid_filters
            self.display_func = display_func
            self.storage_func = storage_func

            self.stop_parser = Event()

            if debug:
                print("[!] ESSID filters: " + str(self.essid_filters))
                print("[!] ESSID regex: " + str(essid_regex))
                print("[!] Ignore case: " + str(ignore_case))

            if essid_regex is not None:
                if ignore_case:
                    self.essid_regex = rcompile(essid_regex, IGNORECASE)
                else:
                    self.essid_regex = rcompile(essid_regex)
            else:
                self.essid_regex = None

        def run(self):
            # The parser continues to do its job even after the call of the
            # join method if the queue is not empty.
            while not self.stop_parser.isSet() or not self.new_packets.empty():
                try:
                    packet = self.new_packets.get(timeout=1)
                    probe_request = self.parse(packet)

                    if not probe_request.essid:
                        continue

                    if self.essid_filters is not None and not probe_request.essid in self.essid_filters:
                        continue

                    if self.essid_regex is not None and not match(self.essid_regex, probe_request.essid):
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
            Parses the packet and returns a probe request object.
            """

            timestamp = packet.getlayer(RadioTap).time
            s_mac = packet.getlayer(RadioTap).addr2
            essid = packet.getlayer(Dot11ProbeReq).info.decode("utf-8")

            return ProbeRequest(timestamp, s_mac, essid)

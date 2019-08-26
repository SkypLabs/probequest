"""
Packet sniffer module.
"""

from scapy.sendrecv import AsyncSniffer


class PacketSniffer:
    """
    Wrapper around the 'AsyncSniffer' class from the Scapy project.
    """

    def __init__(self, config, new_packets):
        self.config = config
        self.new_packets = new_packets

        self.sniffer = AsyncSniffer(
            iface=self.config.interface,
            filter=self.config.generate_frame_filter(),
            store=False,
            prn=self.new_packet
        )

    def start(self):
        """
        Starts the packet sniffer.
        """

        self.sniffer.start()

    def stop(self):
        """
        Stops the packet sniffer.
        """

        self.sniffer.stop()

    def is_running(self):
        """
        Returns true if the sniffer is running, false otherwise.
        """

        return self.sniffer.running

    def new_packet(self, packet):
        """
        Adds the packet given as parameter to the queue to be processed by the
        parser.
        """

        self.new_packets.put(packet)

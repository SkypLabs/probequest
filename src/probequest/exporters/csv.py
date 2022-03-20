"""
Probe request CSV exporter module.
"""

import logging
from csv import writer

from scapy.pipetool import Sink


class ProbeRequestCSVExporter(Sink):
    """
    A probe request CSV exporter.
    """

    def __init__(self, config, name=None):
        self.logger = logging.getLogger(__name__)

        Sink.__init__(self, name=name)

        self.csv_file = config.output_file
        self.csv_writer = None

        if self.csv_file is not None:
            self.csv_writer = writer(self.csv_file, delimiter=";")

        self.logger.info("CSV exporter initialised")

    def push(self, msg):
        if self.csv_writer is not None:
            self.csv_writer.writerow([
                msg.timestamp,
                msg.s_mac,
                msg.s_mac_oui,
                msg.essid
            ])

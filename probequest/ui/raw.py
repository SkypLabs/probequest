#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from probequest.probe_request_sniffer import ProbeRequestSniffer

class RawProbeRequestViewer:
    """
    Displays the raw probe requests passing near the Wi-Fi interface.
    """

    def __init__(self, interface, **kwargs):
        self.output = kwargs.get("output", None)

        if self.output is not None:
            from csv import writer

            outfile = writer(self.output, delimiter=";")

            def write_csv(probe_req):
                outfile.writerow([
                    probe_req.timestamp,
                    probe_req.s_mac,
                    probe_req.s_mac_oui,
                    probe_req.essid
                ])
        else:
            write_csv = lambda p: None

        def display_probe_req(probe_req):
            print(probe_req)

        self.sniffer = ProbeRequestSniffer(
            interface,
            display_func=display_probe_req,
            storage_func=write_csv,
            **kwargs
        )

    def start(self):
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()

        if self.output is not None:
            self.output.close()

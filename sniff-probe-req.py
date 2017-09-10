#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from csv import writer
from os import geteuid
from sys import argv, exit
from argparse import ArgumentParser, FileType

def parseProbeReq(packet):
    timestamp = packet.getlayer(RadioTap).time
    s_mac = packet.getlayer(RadioTap).addr2
    essid = packet.getlayer(Dot11ProbeReq).info.decode("utf-8")

    if essid:
        if "essid_filter" in globals() and not essid in essid_filter:
            return

        print("{timestamp} - {s_mac} -> {essid}".format(timestamp=timestamp, s_mac=s_mac, essid=essid))

        if "outfile" in globals():
            outfile.writerow([timestamp, s_mac, essid])

if __name__ == "__main__":
    ap = ArgumentParser(description="Wi-Fi probe requests sniffer")
    ap.add_argument("-e", "--essid", nargs="+", help="ESSID of the APs to filter (space-separated list)")
    ap.add_argument("-f", "--file", type=FileType("a", encoding="UTF-8"), help="output file to save the captured data (CSV format)")
    ap.add_argument("-i", "--interface", required=True, help="wireless interface to use (must be in monitor mode)")
    ap.add_argument("-s", "--stations", nargs="+", help="MAC addresses of the stations to filter (space-separated list)")
    args = vars(ap.parse_args())

    if not geteuid() == 0:
        exit("[!] You must be root")

    if args["file"]:
        outfile = writer(args["file"], delimiter=";")

    if args["essid"]:
        essid_filter = args["essid"]

    filter = "type mgt subtype probe-req"

    if args["stations"]:
        filter += " && ("

        for i, station in enumerate(args["stations"]):
            if i == 0:
                filter += "ether src host {s_mac}".format(s_mac=station)
            else:
                filter += " || ether src host {s_mac}".format(s_mac=station)

        filter += ")"

    print("[*] Start sniffing probe requests...")

    try:
        sniff(iface=args["interface"], filter=filter, prn=parseProbeReq)
    except IOError:
        exit("[!] Interface doesn't exist")

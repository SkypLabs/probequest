#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from os import geteuid
from sys import argv, exit
from argparse import ArgumentParser

def parseProbeReq(packet):
    timestamp = packet.getlayer(RadioTap).time
    s_mac = packet.getlayer(RadioTap).addr2
    essid = packet.getlayer(Dot11ProbeReq).info.decode("utf-8")

    if essid:
        print("{timestamp} - {s_mac} -> {essid}".format(timestamp=timestamp, s_mac=s_mac, essid=essid))

if __name__ == "__main__":
    ap = ArgumentParser(description="Sniff Wifi probe requests")
    ap.add_argument("-i", "--interface", required=True, help="network interface to use")
    args = vars(ap.parse_args())

    if not geteuid() == 0:
        exit("[!] You must be root")

    print("[*] Start sniffing probe requests...")

    try:
        sniff(iface=args["interface"], filter="type mgt subtype probe-req", prn=parseProbeReq)
    except IOError:
        exit("[!] Interface doesn't exist")

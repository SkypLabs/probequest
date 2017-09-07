#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from os import geteuid
from sys import argv, exit
from argparse import ArgumentParser

def parseProbeReq(packet):
    print(packet.sprintf("{Dot11ProbeReq:%RadioTap.addr2%\t%Dot11Elt.info%}"))

if __name__ == "__main__":
    ap = ArgumentParser(description="Sniff Wifi probe requests")
    ap.add_argument("-i", "--interface", required=True, help="network interface to use")
    args = vars(ap.parse_args())

    if not geteuid() == 0:
        exit("[!] You must be root")

    print("[*] Start sniffing probe requests...")

    sniff(iface=args["interface"], filter="type mgt subtype probe-req", prn=parseProbeReq)

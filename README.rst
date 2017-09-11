============================
Wi-Fi Probe Requests Sniffer
============================

This script allows you to sniff the Wi-Fi probe requests passing near
your wireless interface.

Probe requests are sent by a station to elicit information about access
points, in particular to determine if an access point is present or not
in the nearby environment. Some devices (mostly smartphones and tablets)
use these requests to determine if one of the networks they have
previously been connected to is in range, leaking personal information.

Further details are discussed in `this
paper <https://brambonne.com/docs/bonne14sasquatch.pdf>`__.

Dependencies
============

-  Python 3
-  `Scapy <https://github.com/phaethon/scapy>`__
-  `argparse <https://pypi.python.org/pypi/argparse>`__

Using pip
---------

::

    pip3 install -r requirements.txt

How to
------

::

    usage: sniff-probe-req [-h] [-e ESSID [ESSID ...]]
                           [--exclude EXCLUDE [EXCLUDE ...]] -i INTERFACE
                           [-o OUTPUT] [-r REGEX] [-s STATION [STATION ...]]

    Wi-Fi Probe Requests Sniffer

    optional arguments:
      -h, --help            show this help message and exit
      -e ESSID [ESSID ...], --essid ESSID [ESSID ...]
                            ESSID of the APs to filter (space-separated list)
      --exclude EXCLUDE [EXCLUDE ...]
                            MAC addresses of the stations to exclude (space-
                            separated list)
      -i INTERFACE, --interface INTERFACE
                            wireless interface to use (must be in monitor mode)
      -o OUTPUT, --output OUTPUT
                            output file to save the captured data (CSV format)
      -r REGEX, --regex REGEX
                            regex to filter the ESSIDs
      -s STATION [STATION ...], --station STATION [STATION ...]
                            MAC addresses of the stations to filter (space-
                            separated list)

License
-------

`GPL version 3 <https://www.gnu.org/licenses/gpl.txt>`__

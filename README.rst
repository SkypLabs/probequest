============================
Wi-Fi Probe Requests Sniffer
============================

|Build Status| |Code Coverage| |Dependency Status| |Known Vulnerabilities|

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

This software requires Python 3 and the following dependencies:

-  `argparse <https://pypi.python.org/pypi/argparse>`__
-  `netaddr <https://pypi.python.org/pypi/netaddr>`__
-  `scapy <https://github.com/secdev/scapy>`__

Also, `tcpdump <http://www.tcpdump.org/>`__ has to be installed and in the PATH.

Installation
============

::

    pip3 install --upgrade sniff-probe-req

How to
======

First of all, you need to `enable the monitor mode of your wireless interface <https://github.com/SkypLabs/sniff-probe-req/wiki/Enabling-the-Monitor-Mode>`__.

Then:

::

    usage: sniff-probe-req [-h] [--debug] [-e ESSID [ESSID ...]]
                           [--exclude EXCLUDE [EXCLUDE ...]] -i INTERFACE
                           [--ignore-case] [-o OUTPUT] [-r REGEX]
                           [-s STATION [STATION ...]]

    Wi-Fi Probe Requests Sniffer

    optional arguments:
      -h, --help            show this help message and exit
      --debug               debug mode
      -e ESSID [ESSID ...], --essid ESSID [ESSID ...]
                            ESSID of the APs to filter (space-separated list)
      --exclude EXCLUDE [EXCLUDE ...]
                            MAC addresses of the stations to exclude (space-
                            separated list)
      -i INTERFACE, --interface INTERFACE
                            wireless interface to use (must be in monitor mode)
      --ignore-case         ignore case distinctions in the regex pattern
                            (default: false)
      -o OUTPUT, --output OUTPUT
                            output file to save the captured data (CSV format)
      -r REGEX, --regex REGEX
                            regex to filter the ESSIDs
      -s STATION [STATION ...], --station STATION [STATION ...]
                            MAC addresses of the stations to filter (space-
                            separated list)

For example:

::

    sniff-probe-req -i wlan0

License
=======

`GPL version 3 <https://www.gnu.org/licenses/gpl.txt>`__

.. |Build Status| image:: https://travis-ci.org/SkypLabs/sniff-probe-req.svg
   :target: https://travis-ci.org/SkypLabs/sniff-probe-req
.. |Code Coverage| image:: https://api.codacy.com/project/badge/Grade/16b9e70e51744256b37099ae8fe9132d
   :target: https://www.codacy.com/app/skyper/sniff-probe-req?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=SkypLabs/sniff-probe-req&amp;utm_campaign=Badge_Grade
.. |Dependency Status| image:: https://gemnasium.com/badges/github.com/SkypLabs/sniff-probe-req.svg
   :target: https://gemnasium.com/github.com/SkypLabs/sniff-probe-req
.. |Known Vulnerabilities| image:: https://snyk.io/test/github/SkypLabs/sniff-probe-req/badge.svg
   :target: https://snyk.io/test/github/SkypLabs/sniff-probe-req

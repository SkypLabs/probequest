# Wi-Fi probe requests sniffer

This script allows you to sniff the Wi-Fi probe requests passing near your wireless interface.

Probe requests are sent by a station to elicit information about access points, in particular to determine if an access point is present or not in the nearby environment. Some devices (mostly smartphones and tablets) use these requests to determine if one of the networks they have previously been connected to is in range, leaking personal information.

Further details are discussed in [this paper][sasquatch paper].

## Dependencies

 * Python 3
 * [Scapy][scapy3k]
 * [argparse][argparse]

### Using pip

    pip3 install -r requirements.txt

## How to

    usage: sniff-probe-req.py [-h] [-e ESSID [ESSID ...]]
                              [--exclude EXCLUDE [EXCLUDE ...]] [-f FILE] -i
                              INTERFACE [-s STATION [STATION ...]]

    Wi-Fi probe requests sniffer

    optional arguments:
      -h, --help            show this help message and exit
      -e ESSID [ESSID ...], --essid ESSID [ESSID ...]
                            ESSID of the APs to filter (space-separated list)
      --exclude EXCLUDE [EXCLUDE ...]
                            MAC addresses of the stations to exclude (space-
                            separated list)
      -f FILE, --file FILE  output file to save the captured data (CSV format)
      -i INTERFACE, --interface INTERFACE
                            wireless interface to use (must be in monitor mode)
      -s STATION [STATION ...], --station STATION [STATION ...]
                            MAC addresses of the stations to filter (space-
                            separated list)

## License

[GPL version 3][GPLv3]

 [argparse]: https://pypi.python.org/pypi/argparse "argparse: Python command-line parsing library"
 [GPLv3]: https://www.gnu.org/licenses/gpl.txt "GPL version 3"
 [sasquatch paper]: https://brambonne.com/docs/bonne14sasquatch.pdf "Your mobile phone is a traitor! - Raising awareness on ubiquitous privacy issues with SASQUATCH"
 [scapy3k]: https://github.com/phaethon/scapy "scapy for Python 3"

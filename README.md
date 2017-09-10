# Wi-Fi probe requests sniffer

This script allows you to sniff the Wi-Fi probe requests passing near your wireless interface.

## Dependencies

 * Python 3
 * [Scapy][scapy3k]
 * [argparse][argparse]

### Using pip

    pip3 install -r requirements.txt

## How to

    usage: sniff-probe-req.py [-h] -i INTERFACE [-f FILE]

    Wi-Fi probe requests sniffer

    optional arguments:
      -h, --help            show this help message and exit
      -i INTERFACE, --interface INTERFACE
                            wireless interface to use (must be in monitor mode)
      -f FILE, --file FILE  output file to save the captured data (CSV format)

## License

[GPL version 3][GPLv3]

 [scapy3k]: https://github.com/phaethon/scapy "scapy for Python 3"
 [argparse]: https://pypi.python.org/pypi/argparse "argparse: Python command-line parsing library"
 [GPLv3]: https://www.gnu.org/licenses/gpl.txt "GPL version 3"

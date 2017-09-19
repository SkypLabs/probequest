#!/usr/bin/env python3

from setuptools import setup
from os.path import dirname, abspath, join
from codecs import open

DIR = dirname(abspath(__file__))
VERSION = '0.4.0'

with open(join(DIR, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name = 'sniff-probe-req',
    version = VERSION,
    description = 'Wi-Fi Probe Requests Sniffer',
    long_description = long_description,
    license = 'GPLv3',
    keywords = 'wifi wireless security sniffer',
    author = 'Paul-Emmanuel Raoul',
    author_email = 'skyper@skyplabs.net',
    url = 'https://github.com/SkypLabs/sniff-probe-req',
    download_url = 'https://github.com/SkypLabs/sniff-probe-req/archive/v{0}.zip'.format(VERSION),
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    ],
    scripts = ['sniff-probe-req'],
    install_requires = ['argparse>=1.4.0', 'netaddr>=0.7.19', 'scapy-python3>=0.21'],
)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from codecs import open as fopen
from os.path import dirname, abspath, join
from setuptools import setup, find_packages

from probequest.version import VERSION

DIR = dirname(abspath(__file__))

with fopen(join(DIR, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name = 'probequest',
    version = VERSION,
    description = 'Wi-Fi Probe Requests Sniffer',
    long_description = long_description,
    license = 'GPLv3',
    keywords = 'wifi wireless security sniffer',
    author = 'Paul-Emmanuel Raoul',
    author_email = 'skyper@skyplabs.net',
    url = 'https://github.com/SkypLabs/probequest',
    download_url = 'https://github.com/SkypLabs/probequest/archive/v{0}.zip'.format(VERSION),
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    ],
    packages = find_packages(),
    scripts = ['bin/probequest'],
    test_suite = 'test',
    install_requires = [
        'argparse >= 1.4.0',
        'netaddr >= 0.7.19',
        'scapy >= 2.4.0',
    ],
    extras_require = {
        'docs': [
            'sphinx >= 1.4.0',
            'sphinxcontrib-seqdiag >= 0.8.5',
            'sphinx-argparse >= 0.2.2',
            'sphinx_rtd_theme',
        ],
    },
)

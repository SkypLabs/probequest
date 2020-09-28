#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Setuptools build system configuration file
for ProbeQuest.

See https://setuptools.readthedocs.io.
"""

try:
    from setuptools import setup, find_packages
except Exception as setuptools_not_present:
    raise ImportError(
        "Setuptools is required to install ProbeQuest!"
    ) from setuptools_not_present

from codecs import open as fopen
from os.path import dirname, abspath, join

DIR = dirname(abspath(__file__))

VERSION = "0.7.2"

with fopen(join(DIR, "README.rst"), encoding="utf-8") as f:
    LONG_DESCRIPTION = f.read()

setup(
    name="probequest",
    version=VERSION,
    description="Toolkit for Playing with Wi-Fi Probe Requests",
    long_description=LONG_DESCRIPTION,
    license="GPLv3",
    keywords="wifi wireless security sniffer",
    author="Paul-Emmanuel Raoul",
    author_email="skyper@skyplabs.net",
    url="https://github.com/SkypLabs/probequest",
    download_url="https://github.com/SkypLabs/probequest/archive/v{0}.zip"
    .format(VERSION),
    project_urls={
        "Documentation": "https://probequest.readthedocs.io",
        "Source Code": "https://github.com/SkypLabs/probequest",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Natural Language :: English",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "probequest = probequest.cli:main",
        ]
    },
    python_requires=">=3.5, <4",
    install_requires=[
        "argparse >= 1.4.0",
        "faker_wifi_essid",
        "netaddr >= 0.7.19",
        "scapy >= 2.4.3",
        "urwid>= 2.0.1",
    ],
    extras_require={
        "tests": [
            "flake8",
            "pylint",
            "tox"
        ],
        "docs": [
            "sphinx >= 1.4.0",
            "sphinxcontrib-seqdiag >= 0.8.5",
            "sphinx-argparse >= 0.2.2",
            "sphinx_rtd_theme",
        ],
    },
)

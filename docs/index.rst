.. Sniff-Probe-Req documentation master file, created by
   sphinx-quickstart on Sun Feb 18 20:07:50 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Sniff-Probe-Req's documentation!
===========================================

The Sniff-Probe-Req project consists of Python modules and tools allowing to sniff the Wi-Fi probe requests passing near your wireless interface.

This project has been inspired by `this paper`_.

What are Wi-Fi probe requests?
------------------------------

Probe requests are sent by a station to elicit information about access points, in particular to determine if an access point is present or not in the nearby environment. Some devices (mostly smartphones and tablets) use these requests to determine if one of the networks they have previously been connected to is in range, leaking personal information.

.. include:: installation.rst
.. include:: usage.rst
.. include:: development.rst

.. _this paper: https://brambonne.com/docs/bonne14sasquatch.pdf

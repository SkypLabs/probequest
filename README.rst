==========
ProbeQuest
==========

|PyPI Package| |PyPI Downloads| |PyPI Python Versions| |Build Status| |LGTM
Grade| |LGTM Alerts| |Documentation Status|

Toolkit allowing to sniff and display the Wi-Fi probe requests passing nearby
your wireless interface.

Probe requests are sent by a station to elicit information about access points,
in particular to determine if an access point is present or not in the nearby
environment. Some devices (mostly smartphones and tablets) use these requests
to determine if one of the networks they have previously been connected to is
in range, leaking personal information.

Further details are discussed in `this paper
<https://brambonne.com/docs/bonne14sasquatch.pdf>`__.

.. image:: docs/_static/img/probequest_demo.gif
   :target: https://asciinema.org/a/205172
   :alt: ProbeQuest - Demo

Installation
============

::

    pip3 install --upgrade probequest

Documentation
=============

The project is documented `here
<http://probequest.readthedocs.io/en/latest/>`__.

In the Media
============

ProbeQuest has appeared in the following media:

- `KitPloit
  <https://www.kitploit.com/2018/06/probequest-toolkit-for-playing-with-wi.html>`__
- `Hakin9 Magazine, VOL.13, NO. 05, "Open Source Hacking Tools"
  <https://skyplabs.keybase.pub/Papers/Magazines/Hakin9%20Magazine%2C%20VOL.13%2C%20NO.%2005%2C%20%22Open%20Source%20Hacking%20Tools%22.pdf>`__
- `WonderHowTo
  <https://null-byte.wonderhowto.com/how-to/track-wi-fi-devices-connect-them-using-probequest-0186137/>`__
  (including a `YouTube video <https://www.youtube.com/watch?v=Z8RHMUSYTiA>`__)
- `ShellVoide
  <https://www.shellvoide.com/wifi/wifi-karma-a-brief-guid-on-probe-response-frames/>`__
- `Cyber Pi Projects
  <https://www.cyberpiprojects.com/student-designed-projects>`__ (`Worksheet
  <https://www.cyberpiprojects.com/s/Probequest-Sniffing-Student.pdf>`__)

License
=======

`GPL version 3 <https://www.gnu.org/licenses/gpl.txt>`__

.. |Build Status| image:: https://github.com/SkypLabs/probequest/actions/workflows/test_and_publish.yml/badge.svg?branch=develop
   :target: https://github.com/SkypLabs/probequest/actions/workflows/test_and_publish.yml?query=branch%3Adevelop
   :alt: Build Status Develop Branch

.. |Documentation Status| image:: https://readthedocs.org/projects/probequest/badge/?version=latest
   :target: https://probequest.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. |LGTM Alerts| image:: https://img.shields.io/lgtm/alerts/g/SkypLabs/probequest.svg?logo=lgtm&logoWidth=18
   :target: https://lgtm.com/projects/g/SkypLabs/probequest/alerts/
   :alt: LGTM Alerts

.. |LGTM Grade| image:: https://img.shields.io/lgtm/grade/python/g/SkypLabs/probequest.svg?logo=lgtm&logoWidth=18
   :target: https://lgtm.com/projects/g/SkypLabs/probequest/context:python
   :alt: LGTM Grade

.. |PyPI Downloads| image:: https://img.shields.io/pypi/dm/probequest.svg?style=flat
   :target: https://pypi.org/project/probequest/
   :alt: PyPI Package Downloads Per Month

.. |PyPI Package| image:: https://img.shields.io/pypi/v/probequest.svg?style=flat
   :target: https://pypi.org/project/probequest/
   :alt: PyPI Package Latest Release

.. |PyPI Python Versions| image:: https://img.shields.io/pypi/pyversions/probequest.svg?logo=python&style=flat
   :target: https://pypi.org/project/probequest/
   :alt: PyPI Package Python Versions

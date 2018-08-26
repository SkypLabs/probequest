==========
ProbeQuest
==========

|PyPI Package| |Build Status| |Code Coverage| |Documentation Status|

Toolkit allowing to sniff and display the Wi-Fi probe requests passing near
your wireless interface.

Probe requests are sent by a station to elicit information about access
points, in particular to determine if an access point is present or not
in the nearby environment. Some devices (mostly smartphones and tablets)
use these requests to determine if one of the networks they have
previously been connected to is in range, leaking personal information.

Further details are discussed in `this
paper <https://brambonne.com/docs/bonne14sasquatch.pdf>`__.

Installation
============

::

    pip3 install --upgrade probequest

Documentation
=============

The project is documented `here <http://probequest.readthedocs.io/en/latest/>`__.

In the Media
============

ProbeQuest has appeared in the following media:

- `KitPloit <https://www.kitploit.com/2018/06/probequest-toolkit-for-playing-with-wi.html>`__
- `Hakin9 Magazine, VOL.13, NO. 05, "Open Source Hacking Tools" <https://drive.google.com/open?id=1Jcv1gFUQ_ue1kqmUlqTy6zVfodB2HYNM>`__
- `WonderHowTo <https://null-byte.wonderhowto.com/how-to/track-wi-fi-devices-connect-them-using-probequest-0186137/>`__ (including a `YouTube video <https://www.youtube.com/watch?v=Z8RHMUSYTiA>`__)

License
=======

`GPL version 3 <https://www.gnu.org/licenses/gpl.txt>`__

.. |Build Status| image:: https://travis-ci.org/SkypLabs/probequest.svg
   :target: https://travis-ci.org/SkypLabs/probequest
   :alt: Build Status
.. |Code Coverage| image:: https://api.codacy.com/project/badge/Grade/16b9e70e51744256b37099ae8fe9132d
   :target: https://www.codacy.com/app/skyper/probequest?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=SkypLabs/probequest&amp;utm_campaign=Badge_Grade
   :alt: Code Coverage
.. |Documentation Status| image:: https://readthedocs.org/projects/probequest/badge/?version=latest
   :target: http://probequest.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status
.. |Known Vulnerabilities| image:: https://snyk.io/test/github/SkypLabs/probequest/badge.svg
   :target: https://snyk.io/test/github/SkypLabs/probequest
   :alt: Known Vulnerabilities
.. |PyPI Package| image:: https://badge.fury.io/py/probequest.svg
   :target: https://badge.fury.io/py/probequest
   :alt: PyPI Package

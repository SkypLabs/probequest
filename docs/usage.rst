=====
Usage
=====

Enabling the monitor mode
-------------------------

To be able to sniff the probe requests, your Wi-Fi network interface must be set
to `monitor mode`_.

With `ip` and `iw`
^^^^^^^^^^^^^^^^^^

::

    sudo ip link set <wireless interface> down
    sudo iw <wireless interface> set monitor control
    sudo ip link set <wireless interface> up

For example:

::

    sudo ip link set wlan0 down
    sudo iw wlan0 set monitor control
    sudo ip link set wlan0 up

With `ifconfig` and `iwconfig`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sudo ifconfig <wireless interface> down
    sudo iwconfig <wireless interface> mode monitor
    sudo ifconfig <wireless interface> up

For example:

::

    sudo ifconfig wlan0 down
    sudo iwconfig wlan0 mode monitor
    sudo ifconfig wlan0 up

With `airmon-ng` from aircrack-ng
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To kill all the interfering processes:

::

    sudo airmon-ng check kill

To enable the monitor mode:

::

    sudo airmon-ng start <wireless interface>

For example:

::

    sudo airmon-ng start wlan0

Command line arguments
----------------------

.. argparse::
   :module: probequest.cli
   :func: get_arg_parser
   :prog: probequest

Example of use
^^^^^^^^^^^^^^

::

    sudo probequest wlan0

Here is a sample output:

.. image:: _static/img/probequest_output_example.png

.. _monitor mode: https://en.wikipedia.org/wiki/Monitor_mode

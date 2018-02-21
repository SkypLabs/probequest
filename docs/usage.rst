Usage
-----

Enabling the monitor mode
^^^^^^^^^^^^^^^^^^^^^^^^^

The `sniff-probe-req` script must be used with a wireless interface in monitor mode.

With `ifconfig` and `iwconfig`
""""""""""""""""""""""""""""""

::

    ifconfig down <wireless interface>
    iwconfig <wireless interface> mode monitor
    ifconfig up <wireless interface>

For example:

::

    ifconfig down wlan0
    iwconfig wlan0 mode monitor
    ifconfig up wlan0

With `airmon-ng` from aircrack-ng
"""""""""""""""""""""""""""""""""

To kill all the interfering processes:

::

    airmon-ng check kill

To enable the monitor mode:

::

    airmon-ng start <wireless interface>

For example:

::

    airmon-ng start wlan0

Example of use
^^^^^^^^^^^^^^

::

    sudo sniff-probe-req -i wlan0

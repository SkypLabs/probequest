Usage
-----

Enabling the monitor mode
^^^^^^^^^^^^^^^^^^^^^^^^^

The `sniff-probe-req` script must be used with a wireless interface in monitor mode.

With `ifconfig` and `iwconfig`
""""""""""""""""""""""""""""""

::

    sudo ifconfig down <wireless interface>
    sudo iwconfig <wireless interface> mode monitor
    sudo ifconfig up <wireless interface>

For example:

::

    sudo ifconfig down wlan0
    sudo iwconfig wlan0 mode monitor
    sudo ifconfig up wlan0

With `airmon-ng` from aircrack-ng
"""""""""""""""""""""""""""""""""

To kill all the interfering processes:

::

    sudo airmon-ng check kill

To enable the monitor mode:

::

    sudo airmon-ng start <wireless interface>

For example:

::

    sudo airmon-ng start wlan0

Example of use
^^^^^^^^^^^^^^

::

    sudo sniff-probe-req -i wlan0

Here is a sample output:

.. image:: _static/img/sniff_probe_req_output_example.png

==============================
What are Wi-Fi probe requests?
==============================

Probe requests are sent by a station to elicit information about access points, in particular to determine if an access point is present or not in the nearby environment. Some devices (mostly smartphones and tablets) use these requests to determine if one of the networks they have previously been connected to is in range, leaking their preferred network list (PNL) and, therefore, your personal information.

Below is a typical Wi-Fi authentication process between a mobile station (for example, your smartphone) and an access point (AP):

.. seqdiag::

    seqdiag admin {
      default_fontsize = 14;
      edge_length = 260;

	  autonumber = True;

      "Mobile Station" -> "Access Point" [label = "Probe Request"];
      "Mobile Station" <-- "Access Point" [label = "Probe Response"];
      "Mobile Station" -> "Access Point" [label = "Authentication Request"];
      "Mobile Station" <-- "Access Point" [label = "Authentication Response"];
      "Mobile Station" -> "Access Point" [label = "Association Request"];
      "Mobile Station" <-- "Access Point" [label = "Association Response"];
    }

Step 1 (and therefore, step 2) is optional since the access points announce their presence by broadcasting their name (ESSID) using `beacon frames`_.

.. _beacon frames: https://en.wikipedia.org/wiki/Beacon_frame

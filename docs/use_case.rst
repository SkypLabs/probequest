========
Use Case
========

Let's consider the following simple scenario inspired from a real data collection (the data have been anonymised): a device tries to connect to `John's iPhone`, `CompanyX_staff`, `STARBUCKS-FREE-WIFI` and `VM21ECAB2`. Based on this information, several assumptions can be made:

- The device owner's name is John.
- The device is set in English and its owner speaks this language (otherwise it would have been `iPhone de John` in French, `iPhone von John` in German, etc).
- The device should be a laptop trying to connect to an iPhone in hotspot mode. The owner has consequently at least two devices and is nomad.
- The owner works for CompanyX.
- The owner frequents coffee shops, in particular StarBucks.
- The owner is used to connecting to open Wi-Fi access points.
- `VM21ECAB2` seems to be a home access point and is the only one in the device's PNL. It is likely the owner's place and, consequently, the device's owner is a customer of Virgin Media.

As you can see, the amount of data inferred from these four probe requests is already impressive, but we can go further. Relying on a database of Wi-Fi access points’ location, such as `WIGLE.net`_, it becomes possible to determine the places the device’s owner has previously been to. VM21ECAB2 should be a unique name, easily localisable on a map. Same for CompanyX_staff. If this last one is not unique (because CompanyX has several offices), crossing the data we have can help us in our investigation. For example, if CompanyX is present in several countries, we can assume that the device’s owner lives in a country where both CompanyX and Virgin Media are present. Once we have determined which office it is, we can suppose that the device’s owner is used to stopping in StarBucks located on their way from home to their office.

Profiling a person is the first step to conduct a social engineering attack. The more we know about our target, the better chance the attack has to succeed. Also, because we know which Wi-Fi access points our target’s devices will try to connect to, an evil twin attack is conceivable.

.. _WIGLE.net: https://wigle.net/

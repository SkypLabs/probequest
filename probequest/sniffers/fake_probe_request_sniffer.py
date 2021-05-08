"""
Fake probe request sniffer module.
"""

import logging
from time import sleep

from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.pipetool import ThreadGenSource

from faker import Faker  # pylint: disable=import-error
from faker_wifi_essid import WifiESSID  # pylint: disable=import-error


class FakeProbeRequestSniffer(ThreadGenSource):
    """
    A fake probe request sniffer.

    This pipe source sends periodically fake Wi-Fi ESSIDs for development and
    test purposes.

    This class inherits from 'ThreadGenSource' and not from 'PeriodicSource' as
    this last one only accepts lists, sets and tuples.
    """

    # pylint: disable=too-many-ancestors

    def __init__(self, period, period2=0, name=None):
        self.logger = logging.getLogger(__name__)

        ThreadGenSource.__init__(self, name=name)

        self.fake_probe_requests = FakeProbeRequest()
        self.period = period
        self.period2 = period2

        self.logger.info("Fake probe request sniffer initialised")

    def generate(self):
        # Fix a false positive about not finding '_wake_up'.
        # pylint: disable=no-member

        while self.RUN:
            # Infinite loop until 'stop()' is called.
            for fake_probe_req in self.fake_probe_requests:
                self._gen_data(fake_probe_req)
                sleep(self.period)

            self.is_exhausted = True
            self._wake_up()

            sleep(self.period2)

    def stop(self):
        ThreadGenSource.stop(self)
        self.fake_probe_requests.stop()


class FakeProbeRequest:
    """
    A fake probe request iterator.
    """

    def __init__(self):
        self._fake = Faker()
        self._fake.add_provider(WifiESSID)

        self._should_stop = False

    def __iter__(self):
        return self

    def __next__(self):
        """
        Generator of fake Wi-Fi probe requests.
        """

        # pylint: disable=no-member

        if self._should_stop:
            raise StopIteration

        return RadioTap() \
            / Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=self._fake.mac_address(),
                addr3=self._fake.mac_address()
            ) \
            / Dot11ProbeReq() \
            / Dot11Elt(
                info=self._fake.wifi_essid()
            )

    def stop(self):
        """
        Interrupts the iteration.

        The next time the iterator will be called, a 'StopIteration' exception
        will be raised.
        """

        self._should_stop = True

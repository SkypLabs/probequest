"""
Fake probe request sniffer module.
"""

from time import sleep

from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.pipetool import ThreadGenSource

from faker import Faker
from faker_wifi_essid import WifiESSID


class FakeProbeRequestSniffer(ThreadGenSource):
    """
    A fake probe request sniffer.

    This pipe source sends periodically fake Wi-Fi ESSIDs for development and
    test purposes.

    This class inherits from 'ThreadGenSource' and not from 'PeriodicSource' as
    this last one only accepts lists, sets and tuples.
    """

    def __init__(self, period, period2=0, name=None):
        ThreadGenSource.__init__(self, name=name)

        self.fake_probe_requests = FakeProbeRequest()
        self.period = period
        self.period2 = period2

    def generate(self):
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

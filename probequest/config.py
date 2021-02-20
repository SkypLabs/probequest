"""
ProbeQuest configuration.
"""

import logging
from enum import Enum
from re import compile as rcompile, IGNORECASE


class Mode(Enum):
    """
    Enumeration of the different operational modes
    supported by this software.
    """

    RAW = "raw"
    PNL = "pnl"

    def __str__(self):
        return str(self.value)


class Config:
    """
    Configuration object.
    """

    interface = None

    essid_filters = None
    essid_regex = None
    ignore_case = False

    mac_exclusions = None
    mac_filters = None

    output_file = None

    mode = Mode.RAW
    fake = False
    debug = False

    _compiled_essid_regex = None
    _frame_filter = None

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @property
    def frame_filter(self):
        """
        Generates and returns the frame filter according to the different
        options set of the current 'Config' object.

        The value is cached once computed.
        """

        if self._frame_filter is None:
            self._frame_filter = "type mgt subtype probe-req"

            if self.mac_exclusions is not None:
                self._frame_filter += " and not ("

                for i, station in enumerate(self.mac_exclusions):
                    if i == 0:
                        self._frame_filter += \
                            "ether src host {s_mac}".format(s_mac=station)
                    else:
                        self._frame_filter += \
                            "|| ether src host {s_mac}".format(s_mac=station)

                self._frame_filter += ")"

            if self.mac_filters is not None:
                self._frame_filter += " and ("

                for i, station in enumerate(self.mac_filters):
                    if i == 0:
                        self._frame_filter += \
                            "ether src host {s_mac}".format(s_mac=station)
                    else:
                        self._frame_filter += \
                            "|| ether src host {s_mac}".format(s_mac=station)

                self._frame_filter += ")"

            self.logger.debug("Frame filter: \"%s\"", self._frame_filter)

        return self._frame_filter

    @property
    def compiled_essid_regex(self):
        """
        Returns the compiled version of the ESSID regex.

        The value is cached once computed.
        """

        # If there is a regex in the configuration and it hasn't been compiled
        # yet.
        if self._compiled_essid_regex is None and self.essid_regex is not None:
            self.logger.debug("Compiling ESSID regex")

            if self.ignore_case:
                self.logger.debug("Ignoring case in ESSID regex")

                self._compiled_essid_regex = rcompile(
                    self.essid_regex,
                    IGNORECASE
                )
            else:
                self._compiled_essid_regex = rcompile(self.essid_regex)

        return self._compiled_essid_regex

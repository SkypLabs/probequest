#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ProbeQuest configuration.
"""

from enum import Enum


class Mode(Enum):
    """
    Enumeration of the different operational modes
    supported by this software.
    """

    RAW = "raw"
    PNL = "pnl"

    def __str__(self):
        return self.value


class Config:
    """
    Configuration object.
    """

    interface = None

    essid_filters = None
    essid_regex = None
    ignore_case = True

    mac_exclusions = None
    mac_filters = None

    output_file = None

    mode = Mode.RAW
    fake = False
    debug = False

    _display_func = lambda *args: None  # noqa: E731
    _storage_func = lambda *args: None  # noqa: E731

    @property
    def display_func(self):
        """
        Callback function triggered when a packet needs to be displayed.
        """

        return self._display_func

    @property
    def storage_func(self):
        """
        Callback function triggered when a packet needs to be stored.
        """

        return self._storage_func

    @display_func.setter
    def display_func(self, func):
        if not hasattr(func, "__call__"):
            raise TypeError(
                "The display function property is not a callable object"
            )

        self._display_func = func

    @storage_func.setter
    def storage_func(self, func):
        if not hasattr(func, "__call__"):
            raise TypeError(
                "The storage function property is not a callable object"
            )

        self._storage_func = func

    def generate_frame_filter(self):
        """
        Generates and returns the frame filter according to the different
        options set of the current 'Config' object.
        """

        frame_filter = "type mgt subtype probe-req"

        if self.mac_exclusions is not None:
            frame_filter += " and not ("

            for i, station in enumerate(self.mac_exclusions):
                if i == 0:
                    frame_filter += "\
                        ether src host {s_mac}".format(
                            s_mac=station)
                else:
                    frame_filter += "\
                        || ether src host {s_mac}".format(
                            s_mac=station)

            frame_filter += ")"

        if self.mac_filters is not None:
            frame_filter += " and ("

            for i, station in enumerate(self.mac_filters):
                if i == 0:
                    frame_filter += "\
                        ether src host {s_mac}".format(
                            s_mac=station)
                else:
                    frame_filter += "\
                        || ether src host {s_mac}".format(
                            s_mac=station)

            frame_filter += ")"

        return frame_filter

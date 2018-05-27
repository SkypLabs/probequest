#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urwid

from probequest.probe_request_sniffer import ProbeRequestSniffer

class PNLViewer:
    """
    TUI used to display the PNL of the nearby devices sending
    probe requests.
    """

    palette = [
        ("header_running", "white", "dark green", "bold"),
        ("header_stopped", "white", "dark red", "bold"),
        ("footer", "dark cyan", "dark blue", "bold"),
        ("key", "light cyan", "dark blue", "underline"),
        ("selected", "black", "light green"),
    ]

    footer_text = ("footer", [
        "    ",
        ("key", "P"), " play/pause  ",
        ("key", "Q"), " quit",
    ])

    def __init__(self, interface):
        self.interface = interface
        self.stations = dict()

        self.sniffer = ProbeRequestSniffer(
            self.interface,
            display_func=self.new_probe_req
        )

        self.view = self.setup_view()

    def setup_view(self):
        """
        Returns the root widget.
        """

        self.interface_text = urwid.Text(self.interface)
        self.sniffer_state_text = urwid.Text("Stopped")

        self.header = urwid.AttrWrap(urwid.Columns([
            urwid.Text("Sniffer's state: "),
            self.sniffer_state_text,
            urwid.Text(" Interface: "),
            self.interface_text,
        ]), "header_stopped")
        footer = urwid.AttrWrap(urwid.Text(self.footer_text), "footer")
        vline = urwid.AttrWrap(urwid.SolidFill(u"\u2502"), "line")

        station_panel = urwid.Padding(self.setup_menu("List of Stations", self.stations.keys()), align="center", width=("relative", 90))
        pnl_panel = urwid.Padding(urwid.ListBox(urwid.SimpleListWalker([])), align="center", width=("relative", 90))

        self.station_list = station_panel.base_widget
        self.pnl_list = pnl_panel.base_widget

        body = urwid.Columns([
            station_panel,
            ("fixed", 1, vline),
            pnl_panel,
        ], focus_column=0)

        top = urwid.Frame(
            header=self.header,
            body=body,
            footer=footer,
            focus_part = "body"
        )

        return top

    def setup_menu(self, title, choices):
        """
        Creates and returns a dynamic ListBox object containing
        a title and the choices given as parameters.
        """

        body = [urwid.Text(title), urwid.Divider()]

        for c in choices:
            button = urwid.Button(c)
            urwid.connect_signal(button, "click", self.station_chosen, c)
            body.append(urwid.AttrMap(button, None, focus_map="selected"))

        return urwid.ListBox(urwid.SimpleFocusListWalker(body))

    def new_probe_req(self, probe_req):
        """
        Callback method called on each new probe request.
        """

        if probe_req.s_mac not in self.stations:
            self.stations[probe_req.s_mac] = []
            self.add_station(probe_req.s_mac)

        if not any(essid.text == probe_req.essid for essid in self.stations[probe_req.s_mac]):
            self.stations[probe_req.s_mac].append(urwid.Text(probe_req.essid))

        if len(self.stations.keys()) == 1:
            self.station_list.set_focus(2);
            self.station_chosen(None, probe_req.s_mac)

        self.loop.draw_screen()

    def add_station(self, name):
        """
        Adds a new station to the stations list.
        """

        button = urwid.Button(name)
        urwid.connect_signal(button, "click", self.station_chosen, name)
        self.station_list.body.append(urwid.AttrMap(button, None, focus_map="selected"))

    def station_chosen(self, button, choice):
        """
        Callback method called when a station is selected
        in the stations list.
        """

        self.pnl_list.body = self.stations[choice]

    def start_sniffer(self):
        """
        Starts the sniffer.
        """

        self.sniffer.start()
        self.sniffer_state_text.set_text("Running")
        self.header.set_attr("header_running");

    def stop_sniffer(self):
        """
        Stops the sniffer.
        """

        self.sniffer.stop()
        self.sniffer_state_text.set_text("Stopped")
        self.header.set_attr("header_stopped");

    def toggle_sniffer_state(self):
        """
        Toggles the sniffer's state.
        """

        if self.sniffer.is_running():
            self.stop_sniffer()
        else:
            self.start_sniffer()

    def main(self):
        """
        Starts the TUI.
        """

        self.loop = urwid.MainLoop(self.view, self.palette, unhandled_input=self.unhandled_keypress)
        self.loop.run()

    def exit_program(self):
        """
        Stops and exits the TUI.
        """

        self.sniffer.stop()
        raise urwid.ExitMainLoop()

    def unhandled_keypress(self, key):
        """
        Contains handlers for each keypress that is not handled
        by the widgets being displayed.
        """

        if key in ("q", "Q"):
            self.exit_program()
        elif key in ("p", "P"):
            self.toggle_sniffer_state()
        else:
            return

        return True

"""
Unit tests for the main module.
"""

import unittest

from argparse import Namespace
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO, TextIOWrapper
from os import remove
from os.path import isfile

from probequest import __version__ as VERSION
from probequest.main import get_arg_parser
from probequest.config import Mode


class TestArgParse(unittest.TestCase):
    """
    Tests the argument parser.
    """

    # pylint: disable=too-many-public-methods

    output_test_file = "probequest_test_output.txt"

    def setUp(self):
        """
        Instanciates a new argument parser.
        """

        self.arg_parser = get_arg_parser()

    def tearDown(self):
        """
        Removes test files if any.
        """

        if isfile(self.output_test_file):
            remove(self.output_test_file)

    def test_without_parameters(self):
        """
        Calls the argument parser with an emtpy input.
        """

        with self.assertRaises(SystemExit) as error_code:
            error_output = StringIO()

            with redirect_stderr(error_output):
                self.arg_parser.parse_args([])

        self.assertEqual(error_code.exception.code, 2)

    def test_short_help_option(self):
        """
        Calls the argument parser with the '-h' option.
        """

        with self.assertRaises(SystemExit) as error_code:
            output = StringIO()

            with redirect_stdout(output):
                self.arg_parser.parse_args(["-h"])

        self.assertEqual(error_code.exception.code, 0)

    def test_long_help_option(self):
        """
        Calls the argument parser with the '--help' option.
        """

        with self.assertRaises(SystemExit) as error_code:
            output = StringIO()

            with redirect_stdout(output):
                self.arg_parser.parse_args(["--help"])

        self.assertEqual(error_code.exception.code, 0)

    def test_version_option(self):
        """
        Calls the argument parser with the '--version' option.
        """

        with self.assertRaises(SystemExit) as error_code:
            output = StringIO()

            with redirect_stdout(output):
                self.arg_parser.parse_args(["--version"])

        self.assertEqual(error_code.exception.code, 0)
        self.assertEqual(output.getvalue(), VERSION + "\n")

    def test_default_values(self):
        """
        Calls the argument parser with an empty input and tests the default
        values in the configuration namespace.
        """

        # pylint: disable=no-member

        with self.assertRaises(SystemExit) as error_code:
            error_output = StringIO()

            with redirect_stderr(error_output):
                config = Namespace()
                self.arg_parser.parse_args(
                    [], namespace=config
                )

        self.assertEqual(error_code.exception.code, 2)

        self.assertIsNone(config.interface)
        self.assertIsNone(config.essid_filters)
        self.assertIsNone(config.essid_regex)
        self.assertFalse(config.ignore_case)
        self.assertIsNone(config.mac_exclusions)
        self.assertIsNone(config.mac_filters)
        self.assertIsNone(config.output_file)
        self.assertEqual(config.mode, Mode.RAW)
        self.assertFalse(config.fake)
        self.assertFalse(config.debug)

    def test_short_interface_option(self):
        """
        Calls the argument parser with the '-i' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0"
        ], namespace=config)

        self.assertEqual(config.interface, "wlan0")

    def test_long_interface_option(self):
        """
        Calls the argument parser with the '--interface' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "--interface", "wlan0"
        ], namespace=config)

        self.assertEqual(config.interface, "wlan0")

    def test_without_interface_option(self):
        """
        Calls the argument parser with some options but not the required
        interface one.
        """

        # pylint: disable=no-member

        with self.assertRaises(SystemExit) as error_code:
            error_output = StringIO()

            with redirect_stderr(error_output):
                config = Namespace()
                self.arg_parser.parse_args([
                    "--debug", "--fake"
                ], namespace=config)

        self.assertEqual(error_code.exception.code, 2)

    def test_debug_option(self):
        """
        Calls the argument parser with the '--debug' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "--debug"
        ], namespace=config)

        self.assertTrue(config.debug)

    def test_fake_option(self):
        """
        Calls the argument parser with the '--fake' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "--fake"
        ], namespace=config)

        self.assertTrue(config.fake)

    def test_ignore_case_option(self):
        """
        Calls the argument parser with the '--ignore-case' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "--ignore-case"
        ], namespace=config)

        self.assertTrue(config.ignore_case)

    def test_short_output_option(self):
        """
        Calls the argument parser with the '-o' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "-o", self.output_test_file
        ], namespace=config)

        self.assertIsInstance(config.output_file, TextIOWrapper)
        config.output_file.close()

    def test_long_output_option(self):
        """
        Calls the argument parser with the '--output' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "--output", self.output_test_file
        ], namespace=config)

        self.assertIsInstance(config.output_file, TextIOWrapper)
        config.output_file.close()

    def test_short_essid_option(self):
        """
        Calls the argument parser with the '-e' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "-e", "essid_1", "essid_2", "essid_3"
        ], namespace=config)

        self.assertListEqual(config.essid_filters, [
            "essid_1", "essid_2", "essid_3"
        ])

    def test_long_essid_option(self):
        """
        Calls the argument parser with the '--essid' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "--essid", "essid_1", "essid_2", "essid_3"
        ], namespace=config)

        self.assertListEqual(config.essid_filters, [
            "essid_1", "essid_2", "essid_3"
        ])

    def test_short_regex_option(self):
        """
        Calls the argument parser with the '-r' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "-r", "test_regex"
        ], namespace=config)

        self.assertEqual(config.essid_regex, "test_regex")

    def test_long_regex_option(self):
        """
        Calls the argument parser with the '--regex' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "--regex", "test_regex"
        ], namespace=config)

        self.assertEqual(config.essid_regex, "test_regex")

    def test_essid_regex_mutual_exclusivity(self):
        """
        Calls the argument parser with both '--essid' and '--regex' options,
        which must fail as they are in the same mutually exclusive group.
        """

        # pylint: disable=no-member

        with self.assertRaises(SystemExit) as error_code:
            error_output = StringIO()

            with redirect_stderr(error_output):
                config = Namespace()
                self.arg_parser.parse_args([
                    "-i", "wlan0", "--essid", "essid_1",
                    "--regex", "test_regex"
                ], namespace=config)

        self.assertEqual(error_code.exception.code, 2)

    def test_exclude_option(self):
        """
        Calls the argument parser with the '--exclude' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "--exclude", "aa:bb:cc:dd:ee:ff",
            "ff:ee:dd:cc:bb:aa"
        ], namespace=config)

        self.assertListEqual(config.mac_exclusions, [
            "aa:bb:cc:dd:ee:ff",
            "ff:ee:dd:cc:bb:aa",
        ])

    def test_short_station_option(self):
        """
        Calls the argument parser with the '-s' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "-s", "aa:bb:cc:dd:ee:ff",
            "ff:ee:dd:cc:bb:aa"
        ], namespace=config)

        self.assertListEqual(config.mac_filters, [
            "aa:bb:cc:dd:ee:ff",
            "ff:ee:dd:cc:bb:aa",
        ])

    def test_long_station_option(self):
        """
        Calls the argument parser with the '--station' option.
        """

        # pylint: disable=no-member

        config = Namespace()
        self.arg_parser.parse_args([
            "-i", "wlan0", "--station", "aa:bb:cc:dd:ee:ff",
            "ff:ee:dd:cc:bb:aa"
        ], namespace=config)

        self.assertListEqual(config.mac_filters, [
            "aa:bb:cc:dd:ee:ff",
            "ff:ee:dd:cc:bb:aa",
        ])

    def test_exclude_station_mutual_exclusivity(self):
        """
        Calls the argument parser with both '--exclude' and '--station'
        options, which must fail as they are in the same mutually exclusive
        group.
        """

        # pylint: disable=no-member

        with self.assertRaises(SystemExit) as error_code:
            error_output = StringIO()

            with redirect_stderr(error_output):
                config = Namespace()
                self.arg_parser.parse_args([
                    "-i", "wlan0", "--exclude", "aa:bb:cc:dd:ee:ff",
                    "--station", "ff:ee:dd:cc:bb:aa"
                ], namespace=config)

        self.assertEqual(error_code.exception.code, 2)

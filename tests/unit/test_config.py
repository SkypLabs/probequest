"""
Unit tests for the configuration module.
"""

import logging
import unittest
from re import compile as rcompile, IGNORECASE

from probequest.config import Config, Mode


class TestConfig(unittest.TestCase):
    """
    Unit tests for the 'Config' class.
    """

    def setUp(self):
        """
        Creates a fake package logger.
        """

        self.logger = logging.getLogger("probequest")
        self.logger.setLevel(logging.DEBUG)

    def test_default_values(self):
        """
        Tests the default values.
        """

        config = Config()

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

        self.assertTrue(hasattr(config.display_func, "__call__"))
        self.assertTrue(hasattr(config.storage_func, "__call__"))

        with self.assertLogs(self.logger, level=logging.DEBUG):
            self.assertEqual(
                config.frame_filter,
                "type mgt subtype probe-req"
            )

    def test_bad_display_function(self):
        """
        Assigns a non-callable object to the display callback function.
        """

        with self.assertLogs(self.logger, level=logging.ERROR):
            with self.assertRaises(TypeError):
                config = Config()
                config.display_func = "test"

    def test_bad_storage_function(self):
        """
        Assigns a non-callable object to the storage callback function.
        """

        with self.assertLogs(self.logger, level=logging.ERROR):
            with self.assertRaises(TypeError):
                config = Config()
                config.storage_func = "test"

    def test_frame_filter_with_mac_filtering(self):
        """
        Tests the frame filter when some MAC addresses need to be filtered.
        """

        config = Config()
        config.mac_filters = ["a4:77:33:9a:73:5c", "b0:05:94:5d:5a:4d"]

        with self.assertLogs(self.logger, level=logging.DEBUG):
            self.assertEqual(
                config.frame_filter,
                "type mgt subtype probe-req" +
                " and (ether src host a4:77:33:9a:73:5c" +
                "|| ether src host b0:05:94:5d:5a:4d)"
            )

    def test_frame_filter_with_mac_exclusion(self):
        """
        Tests the frame filter when some MAC addresses need to be excluded.
        """

        config = Config()
        config.mac_exclusions = ["a4:77:33:9a:73:5c", "b0:05:94:5d:5a:4d"]

        with self.assertLogs(self.logger, level=logging.DEBUG):
            self.assertEqual(
                config.frame_filter,
                "type mgt subtype probe-req" +
                " and not (ether src host a4:77:33:9a:73:5c" +
                "|| ether src host b0:05:94:5d:5a:4d)"
            )

    def test_compiled_essid_regex_with_an_empty_regex(self):
        """
        Tests 'compiled_essid_regex' with an empty regex.
        """

        config = Config()
        compiled_regex = config.compiled_essid_regex

        self.assertEqual(compiled_regex, None)

    def test_compiled_essid_regex_with_a_case_sensitive_regex(self):
        """
        Tests 'compiled_essid_regex' with a case-sensitive regex.
        """

        config = Config()
        config.essid_regex = "Free Wi-Fi"

        with self.assertLogs(self.logger, level=logging.DEBUG):
            compiled_regex = config.compiled_essid_regex

        self.assertEqual(compiled_regex, rcompile(config.essid_regex))

    def test_compiled_essid_regex_with_a_case_insensitive_regex(self):
        """
        Tests 'compiled_essid_regex' with a case-insensitive regex.
        """

        config = Config()
        config.essid_regex = "Free Wi-Fi"
        config.ignore_case = True

        with self.assertLogs(self.logger, level=logging.DEBUG):
            compiled_regex = config.compiled_essid_regex

        self.assertEqual(compiled_regex, rcompile(
            config.essid_regex, IGNORECASE))

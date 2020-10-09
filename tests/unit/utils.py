"""
Common assets for the unit tests.
"""

from argparse import Namespace

from probequest.config import Mode


def create_fake_config():
    """
    Creates and returns a fake 'Config' object.
    """

    config = Namespace()

    config.interface = None

    config.essid_filters = None
    config.essid_regex = None
    config.ignore_case = False

    config.mac_exclusions = None
    config.mac_filters = None

    config.output_file = None

    config.mode = Mode.RAW
    config.fake = False
    config.debug = False

    config.display_func = lambda *args: None
    config.storage_func = lambda *args: None
    config.compiled_essid_regex = None
    config.frame_filter = None

    return config

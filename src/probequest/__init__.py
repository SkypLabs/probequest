"""
ProbeQuest package.
"""

import logging

__version__ = "0.8.0"


def set_up_package_logger():
    """
    Sets up the package logger.
    """

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.NullHandler())


set_up_package_logger()

"""
ProbeQuest package.
"""

import logging
from pkg_resources import get_distribution

__version__ = get_distribution("probequest").version


def set_up_package_logger():
    """
    Sets up the package logger.
    """

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.NullHandler())


set_up_package_logger()

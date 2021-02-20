"""
ProbeQuest exceptions module.
"""


class ProbeQuestException(Exception):
    """
    Base class for all exceptions thrown by the probequest module.
    """


class InterfaceDoesNotExistException(ProbeQuestException):
    """
    Thrown when the network interface does not exist.
    """

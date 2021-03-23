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


class DependencyNotPresentException(ProbeQuestException):
    """
    Thrown when an optional dependency is not present on the system.
    """

from enum import Enum


class Injection(Enum):
    """
    Simple Enum class to describe supported SQL injections.
    """

    ERROR_BASED = 1,
    BOOLEAN_BASED = 2

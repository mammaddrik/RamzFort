from enum import Enum, auto


class SessionState(Enum):
    ACTIVE = auto()
    LOCKED = auto()
    CLOSED = auto()
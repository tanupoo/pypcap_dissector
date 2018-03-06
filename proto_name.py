from enum import Enum, unique, auto

@unique
class PROTO(Enum):
    NULL = auto()
    EN10MB = auto()
    IPV4 = auto()
    IPV6 = auto()
    ICMPV6 = auto()
    UDP = auto()
    COAP = auto()


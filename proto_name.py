from enum import Enum, unique, auto

@unique
class PROTO(Enum):
    IPV4 = auto()
    IPV6 = auto()
    ICMPV6 = auto()
    UDP = auto()
    COAP = auto()


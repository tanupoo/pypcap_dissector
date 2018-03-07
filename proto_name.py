from enum import Enum, unique, auto

'''
these are going to be the domain name.
'''
@unique
class PROTO(Enum):
    NULL = auto()
    EN10MB = auto()
    IPV4 = auto()
    IPV6 = auto()
    ICMPV6 = auto()
    UDP = auto()
    COAP = auto()


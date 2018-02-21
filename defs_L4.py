from dissector_icmpv6 import *
from dissector_udp import *

dissectors_L4 = {
    17: dissect_udp,
    58: dissect_icmpv6,
}

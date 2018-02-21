from dissector_ipv6 import *
from dissector_ipv4 import *

dissectors_L3 = {
    4: dissect_ipv4,
    6: dissect_ipv6,
    }

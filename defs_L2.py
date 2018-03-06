import pcap
from dissector_null import *
from dissector_en10mb import *

dissectors_L2 = {
    pcap.DLT_NULL: dissect_null,
    pcap.DLT_EN10MB: dissect_en10mb,
    }

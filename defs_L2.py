import pcap
from dissector_null import dissect_null
from dissector_en10mb import dissect_en10mb

dissectors_L2 = {
    pcap.DLT_NULL: dissect_null,
    pcap.DLT_EN10MB: dissect_en10mb,
    }

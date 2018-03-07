from proto_name import *
from json_keys import *
from defs_L4 import *
from util import *

def dissect_ipv6(x):
    '''
    return { JK_PROTO:PROTO, JK_HEADER:fld, JK_PAYLOAD:(dissectors_L4) }
    or
    return { JK_PROTO:PROTO, JK_EMSG:(error-message) }
    '''
    key_v_tc_fl = "v_tc_fl"
    hdr = (
        (key_v_tc_fl, ">I", 0x60000000),
        (JK_LEN, ">H", 0),
        (JK_NXT, "B", 0),
        (JK_HOP_LIMIT, "B", 0),
        (JK_SADDR, "16s", b"\x00" * 16),
        (JK_DADDR, "16s", b"\x00" * 16),
    )
    this = {}
    domain = PROTO.IPV6.name
    this[JK_PROTO] = domain
    fld, offset, emsg = dissect_hdr(domain, hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    fld[mjk(domain,JK_VER)] = (fld[mjk(domain,key_v_tc_fl)]>>28)
    fld[mjk(domain,JK_TRAFFIC_CLASS)] = (fld[mjk(domain,key_v_tc_fl)]>>24)&0x0ff
    fld[mjk(domain,JK_FLOW_LABEL)] = fld[mjk(domain,key_v_tc_fl)]&0x0fffff
    del(fld[mjk(domain,key_v_tc_fl)])

    this[JK_HEADER] = fld

    proto = fld[mjk(domain,JK_NXT)]
    if proto in dissectors_L4:
        this[JK_PAYLOAD] = dissectors_L4[proto](x[offset:])
        return this
    else:
        this[JK_EMSG] = "unsupported. L4 proto=%d" % proto
        return this


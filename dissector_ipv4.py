from proto_name import *
from json_keys import *
from defs_L4 import *
from util import *

def dissect_ipv4(x):
    '''
    return { JK_PROTO:domain, JK_HEADER:fld, JK_PAYLOAD:dissectors_L4 }
    or
    return { JK_PROTO:domain, JK_EMSG:error-message }
    '''
    hdr = (
        ("v_ihl", "B", 0x40),
        ("TOS", "B", 0),
        ("TOTAL_LEN", ">H", 0),
        ("IDENT", ">H", 0),
        ("f_foff", ">H", 0),
        ("TTL", "B", 0),
        ("NEXT_PROTO", "B", 0),
        ("CHECK_SUM", ">H", 0),
        ("SRC_ADDR", "4s", b"\x00" * 4),
        ("DST_ADDR", "4s", b"\x00" * 4),
    )
    this = {}
    this[JK_PROTO] = PROTO.IPV4.name
    fld, offset, emsg = dissect_hdr(this[JK_PROTO], hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    domain = this[JK_PROTO]
    fld[domain+".VER"] = (fld[domain+".v_ihl"]>>4)&0x0f
    fld[domain+".IHL"] = fld[domain+".v_ihl"]&0x0f
    fld[domain+".FLAGS"] = (fld[domain+".f_foff"]>>5)&0x07
    fld[domain+".F_OFFSET"] = fld[domain+".f_foff"]&0x1fff
    del(fld[domain+".v_ihl"])
    del(fld[domain+".f_foff"])

    this[JK_HEADER] = fld

    proto = fld[domain+".NEXT_PROTO"]
    if proto in dissectors_L4:
        this[JK_PAYLOAD] = dissectors_L4[proto](x[offset:])
        return this
    else:
        this[JK_EMSG] = "unsupported. L4 proto=%d" % proto
        return this

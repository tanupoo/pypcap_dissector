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
    key_f_foff = "f_foff"
    key_v_ihl = "f_v_ihl"
    hdr = (
        (key_v_ihl, "B", 0x40),
        (JK_TOS, "B", 0),
        (JK_LEN, ">H", 0),
        (JK_IDENT, ">H", 0),
        (key_f_foff, ">H", 0),
        (JK_TTL, "B", 0),
        (JK_NXT, "B", 0),
        (JK_CKSUM, ">H", 0),
        (JK_SADDR, "4s", b"\x00" * 4),
        (JK_DADDR, "4s", b"\x00" * 4),
    )
    this = {}
    domain = PROTO.IPV4.name
    this[JK_PROTO] = domain
    fld, offset, emsg = dissect_hdr(domain, hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    fld[mjk(domain,JK_VER)] = (fld[mjk(domain,key_v_ihl)]>>4)&0x0f
    fld[mjk(domain,JK_HDR_LEN)] = fld[mjk(domain,key_v_ihl)]&0x0f
    fld[mjk(domain,JK_FLAG)] = (fld[mjk(domain,key_f_foff)]>>5)&0x07
    fld[mjk(domain,JK_OFFSET)] = fld[mjk(domain,key_f_foff)]&0x1fff
    del(fld[mjk(domain,key_v_ihl)])
    del(fld[mjk(domain,key_f_foff)])

    this[JK_HEADER] = fld

    proto = fld[mjk(domain,JK_NXT)]
    if proto in dissectors_L4:
        this[JK_PAYLOAD] = dissectors_L4[proto](x[offset:])
        return this
    else:
        this[JK_EMSG] = "unsupported. L4 proto=%d" % proto
        return this

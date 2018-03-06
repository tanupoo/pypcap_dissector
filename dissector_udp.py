from proto_name import *
from json_keys import *
from defs_L5 import *
from util import *

def dissect_udp(x):
    '''
    return { JK_PROTO:PROTO, JK_HEADER:fld, JK_PAYLOAD:(dissectors_L5) }
    or
    return { JK_PROTO:PROTO, JK_EMSG:(error-message) }
    '''
    hdr = (
        ("SRC_PORT", ">H", 0),
        ("DST_PORT", ">H", 0),
        ("TOTAL_LEN", ">H", 0),
        ("CHECK_SUM", ">H", 0),
    )
    this = {}
    this[JK_PROTO] = PROTO.UDP.name
    fld, offset, emsg = dissect_hdr(this[JK_PROTO], hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    this[JK_HEADER] = fld

    domain = this[JK_PROTO]
    proto = None
    if fld[domain+".SRC_PORT"] in dissectors_L5:
        proto = fld[domain+".SRC_PORT"]
    elif fld[domain+".DST_PORT"] in dissectors_L5:
        proto = fld[domain+".DST_PORT"]
    if proto != None:
        this[JK_PAYLOAD] = dissectors_L5[proto](x[offset:])
        return this
    else:
        if len(x[offset:]) > 0:
            fld[JK_PAYLOAD] = x[offset:]
        this[JK_EMSG] = ("unsupported. L5 PORT=(%d, %d)" %
                         (fld[domain+".SRC_PORT"], fld[domain+".DST_PORT"]))
        return this

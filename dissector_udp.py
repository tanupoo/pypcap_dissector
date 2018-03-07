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
        (JK_SPORT, ">H", 0),
        (JK_DPORT, ">H", 0),
        (JK_LEN, ">H", 0),
        (JK_CKSUM, ">H", 0),
    )
    this = {}
    domain = PROTO.UDP.name
    this[JK_PROTO] = domain
    fld, offset, emsg = dissect_hdr(domain, hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    this[JK_HEADER] = fld

    proto = None
    if fld[mjk(domain,JK_SPORT)] in dissectors_L5:
        proto = fld[mjk(domain,JK_SPORT)]
    elif fld[mjk(domain,JK_DPORT)] in dissectors_L5:
        proto = fld[mjk(domain,JK_DPORT)]
    if proto != None:
        this[JK_PAYLOAD] = dissectors_L5[proto](x[offset:])
        return this
    else:
        if len(x[offset:]) > 0:
            fld[JK_PAYLOAD] = x[offset:]
        this[JK_EMSG] = ("unsupported. L5 PORT=(%d, %d)" %
                         (fld[mjk(domain,JK_SPORT)], fld[mjk(domain,JK_DPORT)]))
        return this

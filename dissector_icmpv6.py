from proto_name import *
from json_keys import *
from util import *

def dissect_icmpv6(x):
    '''
    return { JK_PROTO:"ICMPV6", "HEADER":fld }
    or
    return { JK_PROTO:"ICMPV6", "EMSG":error-message }
    '''
    hdr = (
        ("TYPE", "B", 0),
        ("CODE", "B", 0),
        ("CKSUM", ">H", 0)
    )
    this = {}
    this[JK_PROTO] = PROTO.ICMPV6.name
    fld, offset, emsg = dissect_hdr(this[JK_PROTO], hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    domain = this[JK_PROTO]
    if len(x[offset:]) > 0:
        fld[JK_PAYLOAD] = x[offset:]

    this[JK_HEADER] = fld

    return this


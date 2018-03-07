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
        (JK_TYPE, "B", 0),
        (JK_CODE, "B", 0),
        (JK_CKSUM, ">H", 0)
    )
    this = {}
    domain = PROTO.ICMPV6.name
    this[JK_PROTO] = domain
    fld, offset, emsg = dissect_hdr(domain, hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    if len(x[offset:]) > 0:
        fld[JK_PAYLOAD] = x[offset:]

    this[JK_HEADER] = fld

    return this


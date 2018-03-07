from proto_name import *
from json_keys import *
from util import *

def dissect_en10mb(x):
    '''
    return { JK_PROTO:"EN10MB", "HEADER":fld }
    or
    return { JK_PROTO:"EN10MB", "EMSG":error-message }
    '''
    hdr = (
        (JK_DMAC, "6s", b"\x00"*6),
        (JK_SMAC, "6s", b"\x00"*6),
        (JK_TYPE, ">H", 0),
    )
    this = {}
    domain = PROTO.EN10MB.name
    this[JK_PROTO] = domain
    fld, offset, emsg = dissect_hdr(domain, hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    this[JK_HEADER] = fld

    return this

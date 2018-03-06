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
        ("DST_MAC", "6s", b"\x00"*6),
        ("SRC_MAC", "6s", b"\x00"*6),
        ("ETH_TYPE", ">H", 0),
    )
    this = {}
    this[JK_PROTO] = PROTO.EN10MB.name
    fld, offset, emsg = dissect_hdr(this[JK_PROTO], hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    domain = this[JK_PROTO]
    this[JK_HEADER] = fld

    return this

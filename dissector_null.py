from proto_name import *
from json_keys import *
from util import *

def dissect_null(x):
    '''
    DLT_NULL
        BSD loopback encapsulation; the link layer header is a 4-byte
        field,  in  host  byte  order,  containing  a  PF_ value from
        socket.h for the network-layer protocol of the packet

    return { JK_PROTO:"NULL", "HEADER":fld }
    or
    return { JK_PROTO:"NULL", "EMSG":error-message }
    '''
    hdr = (
        ("AF", "=L", 0),
    )
    this = {}
    this[JK_PROTO] = PROTO.NULL.name
    fld, offset, emsg = dissect_hdr(this[JK_PROTO], hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    domain = this[JK_PROTO]
    this[JK_HEADER] = fld

    return this

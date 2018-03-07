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
        ("AF", "=I", 0),
    )
    this = {}
    domain = PROTO.NULL.name
    this[JK_PROTO] = domain
    fld, offset, emsg = dissect_hdr(domain, hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    this[JK_HEADER] = fld

    return this

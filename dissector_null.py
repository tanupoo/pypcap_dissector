from json_keys import *
import pypacket_dissector as pd

def dissect_null(x):
    '''
    DLT_NULL
        BSD loopback encapsulation; the link layer header is a 4-byte
        field,  in  host  byte  order,  containing  a  PF_ value from
        socket.h for the network-layer protocol of the packet

    return { JK_PROTO:DLT_NULL, "HEADER":fld }
    or
    return { JK_PROTO:DLT_NULL, "EMSG":error-message }
    '''
    hdr = (
        (JK_DLT_NULL_AF, "=I", 0),
    )
    this = {}
    this[pd.JK_PROTO] = JK_DLT_NULL
    fld, offset, emsg = pd.dissect_hdr(hdr, x)
    if fld == None:
        this[pd.JK_EMSG] = emsg
        return this

    this[pd.JK_HEADER] = fld

    return this

from json_keys import *
import pypacket_dissector as pd

def dissect_en10mb(x):
    '''
    return { JK_PROTO:EN10MB, "HEADER":fld }
    or
    return { JK_PROTO:EN10MB, "EMSG":error-message }
    '''
    hdr = (
        (JK_EN10MB_DMAC, "6s", b"\x00"*6),
        (JK_EN10MB_SMAC, "6s", b"\x00"*6),
        (JK_EN10MB_TYPE, ">H", 0),
    )
    this = {}
    this[pd.JK_PROTO] = JK_EN10MB
    fld, offset, emsg = pd.dissect_hdr(hdr, x)
    if fld == None:
        this[pd.JK_EMSG] = emsg
        return this

    this[pd.JK_HEADER] = fld

    return this

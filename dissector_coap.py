#!/usr/bin/env python
# -*- coding: utf-8 -*-

from proto_name import *
from json_keys import *
from util import *

def dissect_coap(x):
    '''
    return { JK_PROTO:PROTO, "HEADER":fld }
    or
    return { JK_PROTO:PROTO, "EMSG":error-message }
    '''
    hdr = (
        ("v_t_tkl", "B", 0),
        ("CODE", "B", 0),
        ("MID", ">H", 0),
    )
    this = {}
    this[JK_PROTO] = PROTO.COAP.name
    fld, offset, emsg = dissect_hdr(this[JK_PROTO], hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    domain = this[JK_PROTO]
    fld[domain+".VER"] = (fld[domain+".v_t_tkl"]>>6)&0x03
    fld[domain+".TYPE"] = (fld[domain+".v_t_tkl"]>>4)&0x03
    fld[domain+".TOKEN_LEN"] = fld[domain+".v_t_tkl"]&0x07
    del(fld[domain+".v_t_tkl"])

    if fld[domain+".TOKEN_LEN"] > 0:
        try:
            fld[domain+".TOKEN"] = x[:fld[domain+".TOKEN_LEN"]]
        except ValueError as e:
            this[JK_EMSG] = e
            return this
        offset += fld[domain+".TOKEN_LEN"]

    if len(x[offset:]) > 0:
        fld[JK_PAYLOAD] = x[offset:]

    this[JK_HEADER] = fld

    return this

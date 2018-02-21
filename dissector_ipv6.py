#!/usr/bin/env python
# -*- coding: utf-8 -*-

from proto_name import *
from json_keys import *
from defs_L4 import *
from util import *

def dissect_ipv6(x):
    '''
    return { JK_PROTO:PROTO, JK_HEADER:fld, JK_PAYLOAD:(dissectors_L4) }
    or
    return { JK_PROTO:PROTO, JK_EMSG:(error-message) }
    '''
    hdr = (
        ("v_tc_fl", ">I", 0x60000000),
        ("PL_LEN", ">H", 0),
        ("NXT_H", "B", 0),
        ("H_LIM", "B", 0),
        ("SRC_ADDR", "16s", b"\x00" * 16),
        ("DST_ADDR", "16s", b"\x00" * 16),
    )
    this = {}
    this[JK_PROTO] = PROTO.IPV6.name
    fld, offset, emsg = dissect_hdr(this[JK_PROTO], hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    domain = this[JK_PROTO]
    fld[domain+".VER"] = (fld[domain+".v_tc_fl"]>>28)
    fld[domain+".TC"] = (fld[domain+".v_tc_fl"]>>24)&0x0ff      # Trffic Class
    fld[domain+".FL"] = fld[domain+".v_tc_fl"]&0x0fffff         # Trffic Flow
    del(fld[domain+".v_tc_fl"])

    this[JK_HEADER] = fld

    proto = fld[domain+".NXT_H"]
    if proto in dissectors_L4:
        this[JK_PAYLOAD] = dissectors_L4[proto](x[offset:])
        return this
    else:
        this[JK_EMSG] = "unsupported. L4 proto=%d" % proto
        return this


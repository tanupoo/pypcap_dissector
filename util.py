#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
from proto_name import *

def dissect_hdr(domain, hdr_elm, x):
    '''
    domain: protocol name
    hdr_elm: list of the header field format in tuple
    x: header in bytes

    return proto_hdr, offset, None
    or
    return None, offset, error-message
    '''
    hdr_flds = {}
    offset = 0
    for i in hdr_elm:
        fld_fmt = i[1]
        fld_size = struct.calcsize(fld_fmt)
        fld_name = domain + "." + i[0]
        if len(x[offset:]) < fld_size:
            emsg = ("invalid header length, rest:%d < hdr:%d" %
                    (len(x[offset:]), fld_size))
            return None, offset, emsg
        hdr_flds[fld_name] = struct.unpack(fld_fmt, x[offset:offset+fld_size])[0]
        offset += fld_size
    #
    return hdr_flds, offset, None

def ipv6addr(x):
    '''
    x: assuming the length is 16 bytes
    '''
    return ":".join(["%02x%02x"%(x[i],x[i+1]) for i in range(0,16,2)])

def ipv4addr(x):
    '''
    x: assuming the length is 16 bytes
    '''
    return ".".join(["%d"%x[i] for i in range(4)])

def dump_byte(x):
    return "".join([ " %02x"%x[i] if i and i%4==0 else "%02x"%x[i]
                   for i in range(len(x)) ])

def dump_pretty(a, indent="  "):
    for k in a.keys():
        if k in ["IPV6.SRC_ADDR","IPV6.DST_ADDR"]:
            print('%s"%s": "%s"' % (indent, k, ipv6addr(a[k])))
        elif k in ["IPV4.SRC_ADDR","IPV4.DST_ADDR"]:
            print('%s"%s": "%s"' % (indent, k, ipv4addr(a[k])))
        elif isinstance(a[k], (bytes, bytearray)):
            print('%s"%s": "%s"' %
                  (indent, k, "".join(["%02x"%i for i in a[k]])))
        elif isinstance(a[k], dict):
            print('%s"%s": ' % (indent, k))
            dump_pretty(a[k], indent=indent+"  ")
        else:
            print('%s"%s": "%s"' % (indent, k, repr(a[k])))

if __name__ == "__main__":
    print(ipv4addr([0x7f, 0, 0, 1]))
    print(ipv6addr(b"&\x07\xf8\xb0@\x0e\x0c\x04\x00\x00\x00\x00\x00\x00\x00_"))
    print(ipv6addr(b"\x00"*15 + b"\x01"))

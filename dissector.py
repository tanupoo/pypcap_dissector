from proto_name import *
from json_keys import *
from defs_L2 import *
from defs_L3 import *
from util import *

def dissector(x, dloff=0, dltype=None):
    '''
    if dloff is not 0 and dltype is not None, it will dissect L2.

    return (dissectors_L3 or L2)
    or
    return { JK_EMSG:(error-message) }
    '''
    this = None
    if dloff > 0 and dloff < len(x) and dltype != None:
        if dltype in dissectors_L2:
            this = dissectors_L2[dltype](x[:dloff])
        else:
            return { JK_EMSG:"unsupported. L2 proto=%d" % dltype }

    x = x[dloff:]

    # only show ipv6 packets
    if len(x) < 1:
        return { JK_EMSG:"invalid packet length" }

    proto = (x[0]&0xf0)>>4
    if proto in dissectors_L3:
        if this != None:
            this[JK_PAYLOAD] = dissectors_L3[proto](x)
            return this
        else:
            return dissectors_L3[proto](x)
    else:
        return { JK_EMSG:"unsupported. L3 proto=%d" % proto }

if __name__ == "__main__":
    test_packet = [
        bytearray(b'`\x00\x00\x00\x00-\x11\x1e\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x162\x163\x00-\x00\x00A\x02\x00\x01\x82\xb3foo\x03bar\x06ABCD==Fk=eth0\xff\x82\x19\x0bd\x1a\x00\x01\x8e\x96'),
        bytearray(b'`\x12\x34\x56\x00\x1e\x11\x1e\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x162\x163\x00\x1e\x00\x00A\x02\x00\x01\n\xb3foo\xff\x84\x01\x82  &Ehello'),
        bytearray(b'`\x12\x34\x56\x00\x1e\x11\x1e\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x162\x163\x00\x1e\x00\x00A\x02\x00\x01\n\xb3foo\x03bar\x06ABCD==Fk=eth0\xff\x84\x01\x82  &Ehello'),
        bytearray(b'`\x0c_"\x00\x10:@\xfe\x80\x00\x00\x00\x00\x00\x00\xae\xbc2\xff\xfe\xba\x1c\x9f\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x01\xc0\xff\xfe\x06>i\x80\x00J\xc4y\x83\x00\x00Z\x84\x0c|\x00\x00Z\xe4')
        ]

    for i in test_packet:
        ret = dissector(i)
        #print(ret)
        dump_pretty(ret)
        print("===")


from proto_name import *
from json_keys import *
from util import *

def dissect_coap(x):
    '''
    return { JK_PROTO:PROTO, "HEADER":fld }
    or
    return { JK_PROTO:PROTO, "EMSG":error-message }
    '''
    key_v_t_tkl = "v_t_tkl"
    hdr = (
        (key_v_t_tkl, "B", 0),
        (JK_CODE, "B", 0),
        (JK_MSGID, ">H", 0),
    )
    this = {}
    domain = PROTO.COAP.name
    this[JK_PROTO] = domain
    fld, offset, emsg = dissect_hdr(domain, hdr, x)
    if fld == None:
        this[JK_EMSG] = emsg
        return this

    fld[mjk(domain,JK_VER)] = (fld[mjk(domain,key_v_t_tkl)]>>6)&0x03
    fld[mjk(domain,JK_TYPE)] = (fld[mjk(domain,key_v_t_tkl)]>>4)&0x03
    fld[mjk(domain,JK_TOKEN_LEN)] = fld[mjk(domain,key_v_t_tkl)]&0x07
    del(fld[mjk(domain,key_v_t_tkl)])

    if fld[mjk(domain,JK_TOKEN_LEN)] > 0:
        try:
            fld[mjk(domain, TOKEN)] = x[:fld[mjk(domain, TOKEN_LEN)]]
        except ValueError as e:
            this[JK_EMSG] = e
            return this
        offset += fld[mjk(domain, TOKEN_LEN)]

    if len(x[offset:]) > 0:
        fld[JK_PAYLOAD] = x[offset:]

    this[JK_HEADER] = fld

    return this

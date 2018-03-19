from defs_L2 import dissectors_L2
import pypacket_dissector as pd

def dissect_datalink(x, dloff=0, dltype=None):
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
            return { pd.JK_EMSG:"unsupported. L2 proto=%d" % dltype }
    #
    return this


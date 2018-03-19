#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import sys
import pcap
from defs_L2 import dissectors_L2
from dissector_datalink import dissect_datalink
import pypacket_dissector as pd
import argparse
from binascii import a2b_hex

def read_device(devname, direction=pcap.PCAP_D_IN, show_l2=False,
                pkt_filter=None, show_raw=False, delimiter=None,
                verbose=False, debug=False):

    pc = pcap.pcap(devname, immediate=True)
    if verbose:
        print("listening on %s" % devname)
        print("datalink: ", pc.datalink())
        print("dloff: ", pc.dloff)
        print("filter: ", pc.filter)
        print("snaplen: ", pc.snaplen)

    pc.setdirection(direction)
    #
    for ts, data in pc:
        if verbose:
            print(pd.dissector.dump_byte(data))
        # dissect L2
        ret2 = None
        if show_l2:
            ret2 = dissect_datalink(data, dloff=pc.dloff, dltype=pc.datalink())
            if ret2 == False:
                continue
            if debug:
                print(ret2)
        # dissect L3 and upper.
        ret3 = pd.dissector.dissector(data[pc.dloff:])
        if ret3 == False:
            continue
        if debug:
            print(ret3)
        #
        if pkt_filter and not pd.contains(pkt_filter, ret3):
            continue
        #
        if show_raw:
            if show_l2:
                sys.stdout.buffer.write(data)
            else:
                sys.stdout.buffer.write(data[pc.dloff:])
            # add delimiter if needed
            if delimiter:
                sys.stdout.buffer.write(delimiter)
            # flush
            sys.stdout.buffer.flush()
            continue
        print("##", ts)
        print(pd.dump_pretty(ret3, l2=ret2))

def parse_args():
    p = argparse.ArgumentParser(description="a packet dissector.", epilog="")
    p.add_argument("target", metavar="TARGET", type=str,
                   help="device name.")
    p.add_argument("pkt_filter", metavar="FILTER", nargs="*",
                   help="pkt_filter.")
    p.add_argument("--raw", action="store_true", dest="show_raw",
                   help="specify to show raw data.")
    p.add_argument("--delimiter", action="store", dest="_delimiter",
                   default=pd.DELIMITER,
                   help='''specify a delimiter to read a series of data from the
                   stdin. e.g. {:s}'''.format(pd.DELIMITER))
    p.add_argument("--show-l2", action="store_true", dest="show_l2",
                   help="specify to dissect datalink.")
    p.add_argument("-t", action="store", dest="direction",
                   default="in",
                   help="""specify the direction of the capturing,
                   which is either 'in' (default), 'out', 'inout'.""")
    p.add_argument("-v", action="store_true", dest="f_verbose",
                   help="enable verbose mode.")
    p.add_argument("-d", action="store_true", dest="f_debug",
                   help="enable debug mode.")

    args = p.parse_args()
    if args.direction == "in":
        args.direction = pcap.PCAP_D_IN
    elif args.direction == "out":
        args.direction = pcap.PCAP_D_OUT
    elif args.direction == "inout":
        args.direction = pcap.PCAP_D_INOUT
    else:
        print("ERROR: direction must be either 'in', 'out', 'inout'.")
        exit(1)

    if args._delimiter == "":
        args.delimiter = None
    else:
        args.delimiter = a2b_hex(args._delimiter)

    return args

'''
main
'''
opt = parse_args()
read_device(opt.target, direction=opt.direction,
            show_raw=opt.show_raw, show_l2=opt.show_l2,
            delimiter=opt.delimiter, pkt_filter=opt.pkt_filter,
            verbose=opt.f_verbose, debug=opt.f_debug)


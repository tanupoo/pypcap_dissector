#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import sys
import pcap
import dissector
import argparse

def read_file(filename, dloff=0, dltype=None, verbose=False, debug=False):
    if filename == "-":
        data = sys.stdin.buffer.read()
    else:
        data = open(filename).buffer.read()
    #
    if verbose:
        print(dissector.dump_byte(data))
    ret = dissector.dissector(data, dloff=dloff, dltype=dltype)
    print(dissector.dump_pretty(ret))

def read_device(devname, direction=pcap.PCAP_D_IN, pkt_filter=None,
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
            print(dissector.dump_byte(data))
        ret = dissector.dissector(data, dloff=pc.dloff, dltype=pc.datalink())
        if ret == False:
            continue
        if debug:
            print(ret)
        if pkt_filter and not dissector.contains(pkt_filter, ret):
            continue
        print("##", ts)
        print(dissector.dump_pretty(ret))

'''
def read_data(data, dloff=0, dltype=None, verbose=False, debug=False):
    return dissector.dissector(data, dloff=dloff, dltype=dltype)
'''

def parse_args():
    p = argparse.ArgumentParser(description="a packet dissector.",
                                epilog=".")
    p.add_argument("target", metavar="TARGET", type=str,
                   help="device name.")
    p.add_argument("pkt_filter", metavar="FILTER", nargs="*",
                   help="pkt_filter.")
    p.add_argument("-t", action="store", dest="direction",
                   default="in",
                   help="""specify the direction of the capturing,
                   which is either 'in' (default), 'out', 'inout'.""")
    p.add_argument("-f", action="store_true", dest="f_filename",
                   help="""specify the target is the filename containing
                   packet data.  '-' allows the stdin as the input.""")
    p.add_argument("--dloff", action="store", dest="dloff", type=int,
                   default=0,
                   help="""specify the offset of the L3 data in the data file.
                   default is 0, which means that there is no datalink data in
                   the file.""")
    p.add_argument("--dltype", action="store", dest="dltype",
                   default=None,
                   help="specify the type of the datalink.")
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

    return args

'''
main
'''
opt = parse_args()

if opt.f_filename:
    read_file(opt.target, dloff=opt.dloff, dltype=opt.dltype,
                verbose=opt.f_verbose, debug=opt.f_debug)
else:
    read_device(opt.target, direction=opt.direction, pkt_filter=opt.pkt_filter,
                verbose=opt.f_verbose, debug=opt.f_debug)


#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import sys
import pcap
import dissector
import argparse

#filter_rule = pcap.bpf("ip6 and udp")

def pcap_test(devname, direction=pcap.PCAP_D_IN, verbose=False, debug=False):
    try:
        pc = pcap.pcap(devname, immediate=True)
        #pc.setfilter(filter_rule)
    except:
        print(pc.geterr())
        return

    print("listening on %s" % devname)
    print("datalink: ", pc.datalink())
    print("dloff: ", pc.dloff)
    print("filter: ", pc.filter)
    print("snaplen: ", pc.snaplen)

    pc.setdirection(direction)

    #try:
    for ts, pkt in pc:
        ret = dissector.dissector(pkt[pc.dloff:])
        if ret != False:
            print("##", ts)
            if verbose:
                print(dissector.dump_byte(pkt))
            if debug:
                print(ret)
            print(dissector.dump_pretty(ret))
    #except Exception as e:
    #    print(e, pc.geterr())

def parse_args():
    p = argparse.ArgumentParser(description="a packet dissector.",
                                epilog=".")
    p.add_argument("devname", metavar="DEV", type=str, help="device name.")
    p.add_argument("-t", action="store", dest="direction",
                   default="in",
                   help="specify to capture the outbound packet. 'in', 'out', 'inout'.  default is inbound packet only.")
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

if __name__ == '__main__':
    opt = parse_args()
    pcap_test(opt.devname, direction=opt.direction, verbose=opt.f_verbose,
              debug=opt.f_debug)

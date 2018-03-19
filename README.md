pypcap-dissector
================

a pypcap wrapper to capture data from an interface.

## requirement

- python3
- pypcap

In Linux OS, libpcap-dev might be required to install pypcap.

## How to use

Simply try to see loop back interface.

    e.g.
    % pcap_read.py lo0
    ## 1521272548.749818
    "PROTO": "IPV4"
    "HEADER": 
        "IPV4.TOS": "0"
        "IPV4.LEN": "802"
        "IPV4.IDENT": "14466"
        "IPV4.TTL": "64"
        "IPV4.NXT": "6"
        "IPV4.CKSUM": "0"
        "IPV4.SADDR": "127.0.0.1"
        "IPV4.DADDR": "127.0.0.1"
        "IPV4.VER": "4"
        "IPV4.HDR_LEN": "5"
        "IPV4.FLAG": "0"
        "IPV4.OFFSET": "0"
    "EMSG": "unsupported. L4 proto=6"
        :
        : (continue)
        :

You can specify a protocol you want to see.  e.g. IPV6

    e.g.
    % pcap_read.py lo0 ICMPV6
    ## 1521430107.170068
      "PROTO": "IPV6"
      "HEADER": 
        "IPV6.LEN": "16"
        "IPV6.NXT": "58"
        "IPV6.HOP_LMT": "64"
        "IPV6.SADDR": "0000:0000:0000:0000:0000:0000:0000:0001"
        "IPV6.DADDR": "0000:0000:0000:0000:0000:0000:0000:0001"
        "IPV6.VER": "6"
        "IPV6.TC": "96"
        "IPV6.FL": "84771"
      "PAYLOAD": 
        "PROTO": "ICMPV6"
        "HEADER": 
          "ICMPV6.TYPE": "128"
          "ICMPV6.CODE": "0"
          "ICMPV6.CKSUM": "28107"
          "ICMPV6.IDENT": "61598"
          "ICMPV6.SEQNO": "0"
          "PAYLOAD": "5aaf2e5b0002983c"

You can pass the data captured to the stdout with the --raw option
so that you can use other dissector.

    % pcap_read.py --raw en0 ICMPV6.IDENT | packet_dissector.py - 
    ---- 2018-03-19 14:12:35.270708
      "PROTO": "IPV6"
      "HEADER": 
        "IPV6.LEN": "16"
        "IPV6.NXT": "58"
        "IPV6.HOP_LMT": "64"
        "IPV6.SADDR": "2001:0420:5e40:1254:5ce9:5a3b:8433:600c"
        "IPV6.DADDR": "2607:f8b0:4004:0811:0000:0000:0000:2004"
        "IPV6.VER": "6"
        "IPV6.TC": "96"
        "IPV6.FL": "400534"
      "PAYLOAD": 
        "PROTO": "ICMPV6"
        "HEADER": 
          "ICMPV6.TYPE": "128"
          "ICMPV6.CODE": "0"
          "ICMPV6.CKSUM": "50055"
          "ICMPV6.IDENT": "17341"
          "ICMPV6.SEQNO": "0"
          "PAYLOAD": "5aaf46c30004200e"
    ---- 2018-03-19 14:12:35.419769
      "PROTO": "IPV6"
      "HEADER": 
        "IPV6.LEN": "16"
        "IPV6.NXT": "58"
        "IPV6.HOP_LMT": "47"
        "IPV6.SADDR": "2607:f8b0:4004:0811:0000:0000:0000:2004"
        "IPV6.DADDR": "2001:0420:5e40:1254:5ce9:5a3b:8433:600c"
        "IPV6.VER": "6"
        "IPV6.TC": "96"
        "IPV6.FL": "400534"
      "PAYLOAD": 
        "PROTO": "ICMPV6"
        "HEADER": 
          "ICMPV6.TYPE": "129"
          "ICMPV6.CODE": "0"
          "ICMPV6.CKSUM": "49799"
          "ICMPV6.IDENT": "17341"
          "ICMPV6.SEQNO": "0"
          "PAYLOAD": "5aaf46c30004200e"

Please remember that the each packet is separated by the delimiter.
if you want to remote it, use --delimiter "".

## Usage

    usage: pcap_read.py [-h] [--raw] [--delimiter _DELIMITER] [--show-l2]
                        [-t DIRECTION] [-v] [-d]
                        TARGET [FILTER [FILTER ...]]
    
    a packet dissector.
    
    positional arguments:
      TARGET                device name.
      FILTER                pkt_filter.
    
    optional arguments:
      -h, --help            show this help message and exit
      --raw                 specify to show raw data.
      --delimiter _DELIMITER
                            specify a delimiter to read a series of data from the
                            stdin. e.g. 00ff707970636170ff00
      --show-l2             specify to dissect datalink.
      -t DIRECTION          specify the direction of the capturing, which is
                            either 'in' (default), 'out', 'inout'.
      -v                    enable verbose mode.
      -d                    enable debug mode.


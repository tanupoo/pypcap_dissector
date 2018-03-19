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

Please remember that the separator of each packet is *b"\x00\x01\x02SEP\xff"*.


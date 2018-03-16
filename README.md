pypcap-dissector
================

Yet another IP packet dissector.

It is going to support a small set of protocols that I need,
such as IPv6, IPv4, UDP, CoAP.

If you want a full set of dissectors, use dpkt, scapy or something like that.

## goal

- simple, lightweight
- pcap base so that it can work on MacOSX.
- python3
- json fiendly

## requirement

- python3
- pypcap if you want to dissect the pcap format file or stream.

In Linux OS, libpcap-dev might be required to install pypcap.

## How to use

Simply try to see loop back interface.

    % packet-dissector.py lo0

You can dissect data in the file you specified or stdin.

    % cat test.dat | ./packet-dissector.py -f - 
      "PROTO": "IPV6"
      "HEADER": 
        "IPV6.PL_LEN": "14"
        "IPV6.NXT_H": "17"
        "IPV6.H_LIM": "64"
        "IPV6.SRC_ADDR": "fe80:0000:0000:0000:aebc:32ff:feba:1c9f"
        "IPV6.DST_ADDR": "fe80:0000:0000:0000:0201:c0ff:fe06:3e69"
        "IPV6.VER": "6"
        "IPV6.TC": "96"
        "IPV6.FL": "694078"
      "PAYLOAD": 
        "PROTO": "UDP"
        "HEADER": 
          "UDP.SRC_PORT": "50145"
          "UDP.DST_PORT": "9999"
          "UDP.TOTAL_LEN": "14"
          "UDP.CHECK_SUM": "63356"
          "PAYLOAD": "48656c6c6f0a"
        "EMSG": "unsupported. L5 PORT=(50145, 9999)"


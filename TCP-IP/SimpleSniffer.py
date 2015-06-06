#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
通常情况下，我们使用wireshark来抓包分析
这个代码只是一份简单抓包的程序，实际生差中，可以据此来拓展自己的工具
"""

import sys
import getopt
import pcapy
from impacket.ImpactDecoder import EthDecoder

dev = "eth0"
filter = "arp"
decoder = EthDecoder()


#每个包都会调用这个函数，用于打印
def handle_packet(hdr, data):
    print decoder.decode(data)


def usage():
    print sys.argv[0] + " -i <dev> -f <pcap_filter>"
    sys.exit(1)


# 传递参数
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

# 在混杂模式下打开设备
pcap = pcapy.open_live(dev, 1500, 0, 100)

# 设置过滤器
pcap.setfilter(filter)

# 开始监听
pcap.loop(0, handle_packet)

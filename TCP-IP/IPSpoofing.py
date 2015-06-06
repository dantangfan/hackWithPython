#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
IP地址欺骗中，攻击者伪造自己的IP地址来发送数据包。
这样就形成了只发包，自己不用收到包的情况
在本例中，我们发送ICMP-Echo——Request也就是Ping包
"""
import sys
from scapy.all import send, IP, ICMP

if len(sys.argv) < 3:
    print sys.argv[0] + " <src_ip> <dst_ip>"
    sys.exit(1)

packet = IP(src=sys.argv[1], dst=sys.argv[2]) / ICMP()
answer = send(packet)

if answer:
    answer.show()
    #pass

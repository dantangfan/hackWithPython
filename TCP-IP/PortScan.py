#!/usr/bin/env python
# coding: utf-8

"""
和传统的端口检测方式一样，这里也是对每个端口逐个尝试。
不同的是，这段代码会尝试三次握手，握手成功后的才是开放的。
"""
import sys
from scapy.all import sr, IP, TCP

if len(sys.argv) < 2:
    print sys.argv[0] + " <host> <spoofed_source_ip>"
    sys.exit(1)

# 发送SYN包去检测前1024个端口
if len(sys.argv) == 3:
    packet = IP(dst=sys.argv[1], src=sys.argv[2])
else:
    packet = IP(dst=sys.argv[0])

packet /= TCP(dport=range(1,1025), flags="S")

answered, unanswered = sr(packet, timeout=1)

res = {}

# 没有响应的包就是被过滤的端口
for packet in unanswered:
    res[packet.dport] = "filtered"

# 有响应的包就是开放的端口
for (send, recv) in answered:
    # 获取ICMP错误信息
    if recv.getlayer("ICMP"):
        type = recv.getlayer("ICMP").type
        code = recv.getlayer("ICMP").code
        # 不可到到的端口
        if code == 3 and type ==3:
            res[send.dport] = "closed"
        else:
            res[send.dport] = "Got ICMP with type" + \
                    str(type) + \
                    " and code " + \
                    str(code)
    else:
        flags = recv.getlayer("TCP").sprintf("%flags%")

        # got SYN/ACK
        if flags == "SA":
            res[send.dport] = 'open'
        # got RST
        elif flags == "R" or flags == "RA":
            res[send.dport] = 'closed'
        # something else
        else:
            res[send.dport] = "Got packet with flags " + str(flags)

#print res
ports = res.keys()
ports.sort()

for port in ports:
    if res[port] != "closed":
        print str(port) + ": " + res[port]

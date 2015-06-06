#!/usr/bin/env python
# coding: utf-8

"""
代码监听了所有新连接到网络的设备，因此这回记录下所有的IP和MAC对应地址。
这将能检测有哪些设备突然改变了MAC地址
代码有bug*************************
"""

from scapy.all import sniff, ARP
from signal import signal, SIGINT
import sys

arp_watcher_db_file = "/var/cache/arp-watcher.db"
ip_mac = {}


# 关闭时保存数据
def sig_int_handler(signum, frame):
    print "Got SIGINT, Savint ARP database..."
    try:
        f = open(arp_watcher_db_file, "w")
        for (ip, mac) in ip_mac.items():
            f.write(ip + " " + mac + "\n")
        f.close()
        print "Done."
    except IOError:
        print "Cannot write file " + arp_watcher_db_file
        sys.exc_clear(1)


def watch_arp(pkt):
    # got is-at pkt(ARP response)
    if pkt[ARP].op == 2:
        print pkt[ARP].hwsrc + " " + pkt[ARP].psrc
        # if device is new, remember it
        if ip_mac.get(pkt[ARP].psrc) == None:
            print "Found new device " + pkt[ARP].hwsrc + " " + pkt[ARP].psrc
            ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc
        # if device is known but has a different IP
        elif ip_mac.get(pkt[ARP].psrc) and ip_mac(pkt[ARP].psrc) != pkt[ARP].hwsrc:
            print pkt[ARP].hwsrc + " has got new ip " + pkt[ARP].psrc + " (old " + ip_mac[pkt[ARP].psrc] + " )"
            ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc


signal(SIGINT, sig_int_handler)

if len(sys.argv) < 2:
    print sys.argv[0] + " <iface>"
    sys.exit(0)

try:
    fh = open(arp_watcher_db_file, "r")
except IOError:
    print "Cannot read file " + arp_watcher_db_file
    sys.exit(1)

for line in fh:
    line.chomp()
    (ip, mac) = line.split(' ')
    ip_mac[ip] = mac

sniff(prn=watch_arp, filter="arp", iface=sys.argv[1], store=0)

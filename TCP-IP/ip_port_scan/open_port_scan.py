#! /usr/bin/env python
# coding:utf-8

import sys
import socket
import thread
import time
socket.setdefaulttimeout(3)

def socket_port(ip, port):
    try:
        if port >= 65535:
            print u'端口是0-65535之间的数字'
        s = socket.socket()
        result = s.connect_ex((ip, port))
        if result==0:
            print ip,u':',port,u'开放'
        s.close()
    except:
        print u'端口扫描异常'

def IP_port(ip, ports = 1, porte = 65535):
    try:
        t = time.time()
        for i in range(ports, porte):
            thread.start_new_thread(socket_port,(ip, int(i)))
            time.sleep(0.01)
        print u'扫描完成，用时%f秒' % (time.time()-t)
    except:
        print u'端口扫描异常'

if __name__=="__main__":
    if len(sys.argv) == 2:
        IP_port(sys.argv[1])
    if len(sys.argv) == 4:
        IP_port(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
    else:
        print """usage: python open_port_scan.py ip [port_start port_end]"""

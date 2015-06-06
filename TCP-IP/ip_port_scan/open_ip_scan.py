#! /usr/bin/env python
# coding:utf-8

import sys
import os
import socket
import threading,time
import thread
socket.setdefaulttimeout(10)


class worker(threading.Thread):
    def __init__(self, ip1, ip2):
        super(worker, self).__init__()
        self.ip1 = ip1
        self.ip2 = ip2

    def run(self):
        list_ip = self.get_ip(self.ipToNum(ip1), self.ipToNum(ip2))
        print u'需要扫描' + str(len(list_ip)) + u'个IP'
        index = 0
        port = 80
        while index < len(list_ip):
            thread.start_new_thread(self.IP_port, (list_ip[index], port))
            time.sleep(0.01)
            index += 1

    def IP_port(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((ip, port))
            if result == 0:
                print ip, u':', port, u'开放'
                xxx = open('ip.txt','a+')
                xxx.seek(1)
                xxx.write(str(ip)+u':'+str(port))
                xxx.write('\n')
                xxx.close()
            s.close()
        except:
            print u'端口扫描异常'

    def ipToNum(self, ip):
        ip = [int(x) for x in ip.split('.')]
        return ip[0]<<24 | ip[1]<<16 | ip[2]<<8 | ip[3]

    def numToIP(self, num):
        return '%s.%s.%s.%s' % ((num & 0xff000000) >> 24,
                                (num & 0x00ff0000) >> 16,
                                (num & 0x0000ff00) >> 8,
                                (num & 0x000000ff)
                                )

    def get_ip(self, ip1, ip2):
        return [self.numToIP(num) for num in range(ip1, ip2+1) if num & 0xff]

if __name__ == "__main__":
    if len(sys.argv) == 3:
        os.system('rm ip.txt')
        os.system('touch ip.txt')
        ip1 = sys.argv[1]
        ip2 = sys.argv[2]
        worker1 = worker(ip1, ip2)
        worker1.start()
    else:
        print u'使用80端口测试ip是否开放'
        print 'usage: ./open_ip_scan.py ip_start ip_end'

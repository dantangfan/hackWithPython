#!/usr/bin/evn python
# coding: utf-8

"""
Referer可以被修改，因此cookie等任何信息都可以被修改。
一般使用fiddler等工具修改，转发
"""
import sys
import httplib2

if len(sys.argv) < 2:
    print sys.argv[0] + ": <url>"
    sys.exit(1)

headers = {'Referer': 'http://www.baidu.com'}
webclient = httplib2.Http()
response, content = webclient.request(sys.argv[1], "GET", headers=headers)
print content

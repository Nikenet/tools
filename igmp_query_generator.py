from scapy.all import *
from scapy.contrib.igmp import IGMP

def getmac(interface):
	try:
		mac = open('/sys/class/net/' + interface + '/address').readline()
	except:
		mac = "00:00:00:00:00:00"

	return mac[0:17]

# Settings
interface  = 'enp2s0'
group_addr = '225.0.0.5'
dst_addr   = '225.0.0.5'
src_addr   = '172.10.1.2'
igmp_type  = 0x11

# Package builds
eth  = Ether(src=getmac(interface))
iph  = IP(src=src_addr, dst=dst_addr, proto=2, ttl=1)
igmp = IGMP(type=igmp_type, gaddr=group_addr)

packet_query = eth/iph/igmp
packet_query.show()

# Sending
print '###[ Start ]###'
sendp(packet_query, iface=interface, verbose=0, loop=1, inter=5)
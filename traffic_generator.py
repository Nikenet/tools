from scapy.all import *
from sys import *

if len(sys.argv) != 2:
	print "Syntax: <interface>"
	exit(0)

def getmac(interface):
	try:
		mac = open('/sys/class/net/' + argv[1] + '/address').readline()
	except:
		mac = "00:00:00:00:00:00"

	return mac[0:17]

packet = \
	Ether(src = getmac(argv[1]), dst = RandMAC()) \
	/ Dot1Q(vlan=50)\
	/ IP(src = RandIP() , dst = RandIP()) \
	/ UDP(sport = 3423, dport = 5342) \
	/ "UDP Random traffic generator"
packet.show()
sendp(packet, iface = argv[1] , loop = 1, verbose = 0)

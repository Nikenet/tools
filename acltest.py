from scapy.all import *
from sys import *

def ACL_type_handler (type):
	if type == 'MAC':
		pack = Ether(src='bc:ae:c5:da:0c:e3',dst='08:00:27:13:30:7f')/ IP(src='20.20.20.10',dst='20.20.20.1', tos=52)
		pack.show()
		return pack
	if type == 'IP':
		pack = Ether(src='bc:ae:c5:da:0c:e3',dst='08:00:27:13:30:7f')/ IP(src='192.168.1.5',dst='192.168.1.6')
		pack.show()
		return pack
	if type == 'IPv6':
		pack = Ether(src='bc:ae:c5:da:0c:e3',dst='08:00:27:13:30:7f')/ IPv6(src='22ff::1',dst='22ff::2')
		pack.show()
		return pack
	if type == 'UDP':
		pack = Ether()/IP(src='192.168.1.5',dst='192.168.1.164')/UDP(sport=1234, dport=1024)
		pack.show()
		return pack
	if type == 'TCP':
		pack = Ether()/IP(src='192.168.1.5',dst='192.168.1.164')/TCP(sport=1234, dport=16660)
		pack.show()
		return pack

if len(sys.argv) != 3:
	print "Syntax: <interface>  <ACL name: MAC/IP/IPv6/TCP/UDP >"
	exit(0)

sendp(ACL_type_handler(argv[2]), iface = argv[1], verbose = 0, count = 10)


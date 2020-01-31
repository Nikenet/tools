import scapy.all
from scapy.all import *

interface = 'enp3s0'


#  Structure of a L2TP's packet in a raw:
#  Ether / IP / UDP/ L2TP / <Data>

# l2 = Ether(src="DE:AD:00:00:BE:EF", type=2048)
# l3 = IP(src='192.168.10.1', dst='192.168.10.5')
# l4 = UDP(sport=1701, dport=1701)
# l2tunnel = L2TP(pkg_type=2)
# stp = STP(bpdutype=128)
p = Ether(src="DE:AD:00:00:BE:EF", dst=RandMAC())/LLC()/STP(bpdutype=2)

#Ether / IP / UDP/ L2TP / PADDING
# Packet = l2 / l3 / l4 / l2tunnel / STP(bpdutype=128)
# sendp(Packet, iface=interface)

#stp bpdu raw bytes

#native mac
r = "\x01\x80\xc2\x00\x00\x00\xe8\x28\xc1\x0c\x5c\xca\x00\x69\x42\x42" \
	"\x03\x00\x00\x03\x02\x7c\x80\x00\xe8\x28\xc1\x0c\x5c\xc0\x00\x00" \
	"\x00\x00\x80\x00\xe8\x28\xc1\x0c\x5c\xc0\x80\x0a\x00\x00\x14\x00" \
	"\x02\x00\x0f\x00\x00\x00\x40\x00\x65\x38\x3a\x32\x38\x3a\x63\x31" \
	"\x3a\x30\x63\x3a\x35\x63\x3a\x63\x30\x00\x00\x00\x00\x00\x00\x00" \
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x36\x17\x7f\x50\x28" \
	"\x3c\xd4\xb8\x38\x21\xd8\xab\x26\xde\x62\x00\x00\x00\x00\x80\x00" \
	"\xe8\x28\xc1\x0c\x5c\xc0\x14"
# changed mac
rd = "\x01\x23\x45\x67\x89\x10\xe8\x28\xc1\x0c\x5c\xca\x00\x69\x42\x42" \
     "\x03\x00\x00\x03\x02\x7c\x80\x00\xe8\x28\xc1\x0c\x5c\xc0\x00\x00" \
     "\x00\x00\x80\x00\xe8\x28\xc1\x0c\x5c\xc0\x80\x0a\x00\x00\x14\x00" \
     "\x02\x00\x0f\x00\x00\x00\x40\x00\x65\x38\x3a\x32\x38\x3a\x63\x31" \
     "\x3a\x30\x63\x3a\x35\x63\x3a\x63\x30\x00\x00\x00\x00\x00\x00\x00" \
     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x36\x17\x7f\x50\x28" \
     "\x3c\xd4\xb8\x38\x21\xd8\xab\x26\xde\x62\x00\x00\x00\x00\x80\x00" \
     "\xe8\x28\xc1\x0c\x5c\xc0\x14"


sendp(rd, iface=interface, loop=0, verbose = 0)
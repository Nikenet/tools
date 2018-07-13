from scapy.all import *
from sys import *

interface = 'enp2s0'

packUDP = Ether(src='10:7b:44:53:39:f3')/IP(src='192.168.1.5',dst='192.168.1.164')/UDP(sport=1234, dport=1024)
packTCP = Ether(src='bc:ae:c5:da:0c:e3')/IP(src='172.10.25.55',dst='172.10.25.15')/TCP(sport=1234, dport=16660)

while True:
	time.sleep(1)
	sendp(packUDP, iface=interface, verbose=0)
	sendp(packTCP, iface=interface, verbose=0)
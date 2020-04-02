from scapy.all import *
from sys import *
import sys
import argparse

parser = argparse.ArgumentParser(description='sQinq test tool')

parser.add_argument('-i', dest='iface',   type=str,                      required=True,  help="Interface"          )
parser.add_argument('-t', dest='tag'  ,   type=int,                      required=True,  help="Inner vlan tag"     )
parser.add_argument('-l', dest='loop'             , action='store_true', required=False, help="Loop(True/False)"   )
parser.add_argument('-v', dest='verbose'          , action='store_true', required=False, help="Verbose(True/False)")

args = parser.parse_args()

ETH      = Ether (src = RandMAC(), dst = RandMAC())
INNERTAG = Dot1Q (vlan=args.tag)
IP       = IP    (src=RandIP(), dst=RandIP())
UDP      = UDP   (sport=9000, dport=8000)
PAYLOAD  = "Selective QinQ test tool"

ifloop    = 0
ifverbose = 0

if args.verbose:
	ifverbose = 1

if args.loop:
	ifloop = 1

packet = ETH / INNERTAG / IP / UDP / PAYLOAD

sendp (packet, iface = args.iface, loop = ifloop, verbose = ifverbose)

#work it progress
# def SendPacket ():
# 	sendp(packet, iface = sdiface, loop=1, verbose = 0)
 
# def SniffPacket ():
# 	s = sniff(iface = sfiface, filter="vlan", prn=print_packet, timeout=5)

# def print_packet(packet):
# 	packet.show()

# threadSniff  = threading.Thread(target = SniffPacket)
# threadPacket = threading.Thread(target = SendPacket)

# threadSniff.start ()
# threadPacket.start ()




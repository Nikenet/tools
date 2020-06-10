from scapy.all import *
from sys import *
import sys
import argparse

parser = argparse.ArgumentParser(description='sQinq test tool')

parser.add_argument('-i'   , dest='iface' ,   type=str,                         required=True,  help="Interface"          )
parser.add_argument('-otag', dest='otag'  ,   type=int,                         required=False, help="Outer vlan tag"     )
parser.add_argument('-itag', dest='itag'  ,   type=int,                         required=False, help="Inner vlan tag"     )
parser.add_argument('-l'   , dest='loop'                 , action='store_true', required=False, help="Loop(True/False)"   )
parser.add_argument('-v'   , dest='verbose'              , action='store_true', required=False, help="Verbose(True/False)")

args = parser.parse_args()

ETH     = Ether (src = RandMAC(), dst = RandMAC())
OTAG    = Dot1Q (vlan=args.otag)
ITAG    = Dot1Q (vlan=args.itag)
IP      = IP    (src=RandIP(), dst=RandIP())
UDP     = UDP   (sport=9000, dport=8000)
PAYLOAD = "Selective QinQ test tool"

ifloop    = 0
ifverbose = 0

if args.verbose:
	ifverbose = 1

if args.loop:
	ifloop = 1

packet_untag     = ETH / IP / UDP / PAYLOAD
packet_tag       = ETH / OTAG / IP / UDP / PAYLOAD
packet_doubletag = ETH / OTAG / ITAG / IP / UDP / PAYLOAD

if args.otag is not None and args.itag is not None :
	print ("Send double tag")
	sendp (packet_doubletag, iface = args.iface, loop = ifloop, verbose = ifverbose)
	exit(0)
elif args.otag is not None:
	print ("Send outer tag")
	sendp (packet_tag, iface = args.iface, loop = ifloop, verbose = ifverbose)
	exit(0)
else:
	print ("Send untag")
	sendp (packet_untag, iface = args.iface, loop = ifloop, verbose = ifverbose)
	exit(0)

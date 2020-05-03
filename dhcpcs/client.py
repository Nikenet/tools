#!/usr/bin/env python

# Scapy based DHCP client

from scapy.all import *
from sys import *
import logging as log

#configuration
interface = 'enp2s0f1'
localmac = RandMAC (template="00:a0:3f")
transactionId = RandInt()

log.basicConfig(stream=sys.stdout, level=logging.DEBUG)

log.addLevelName(logging.DEBUG, "\033[1;33m[?]\033[1;0m")
log.addLevelName(logging.INFO,  "\033[1;35m[#]\033[1;0m")
log.addLevelName(logging.ERROR, "\033[1;31m[!]\033[1;0m")

scapy.all.conf.checkIPaddr = False

def dhcp_discover():

	Eth   = Ether (src=localmac, dst='ff:ff:ff:ff:ff:ff')
	Ip    = IP (src='0.0.0.0', dst='255.255.255.255')
	Udp   = UDP (dport=67, sport=68)
	Bootp = BOOTP (chaddr=localmac.replace(':','').decode ('hex'), xid = transactionId)
	Dhcp  = DHCP (options=[('message-type', 'discover'), 'end'])

	dhcp_discover = Eth / Ip / Udp / Bootp / Dhcp

	return dhcp_discover

def dhcp_request(offer_packet):

	Eth   = Ether (src=localmac, dst='ff:ff:ff:ff:ff:ff')
	Ip    = IP (src='0.0.0.0', dst='255.255.255.255')
	Udp   = UDP (dport=67, sport=68)
	Bootp = BOOTP (chaddr=localmac.replace(':','').decode ('hex'), xid =  transactionId)
	Dhcp  = DHCP (options=[("message-type","request"), 
		                   ("server_id",offer_packet.siaddr), 
		                   ("requested_addr",offer_packet.yiaddr), 
		                   ("end")])

	dhcp_request = Eth / Ip / Udp / Bootp / Dhcp
	return dhcp_request

def handle_dhcp_packet(packet):

	if packet is None:
		log.error("Wrong packet")
		exit(-1)
	packet.summary()
	if packet[DHCP] and packet[DHCP].options[0][1] == 2:
		log.info  ("Accepted DHCP offer")
		log.debug ("Source MAC %s", packet.src)
		log.debug ("Destination MAC %s", packet.dst)
		log.debug ("Transaction ID 0x%x", packet.xid)
		sendp(dhcp_request(packet), iface = interface, count=1, verbose = 0)
		log.info  ("Send DHCP request")

	if packet[DHCP] and packet[DHCP].options[0][1] == 5:
		log.info  ("Accepted DHCP ask")
		log.debug ("Source MAC %s", packet.src)
		log.debug ("Destination MAC %s", packet.dst)
		log.debug ("Transaction ID 0x%x", packet.xid)
		log.debug ("Server IP %s", packet.siaddr)
		log.debug ("Requested IP %s", packet.yiaddr)
		exit (0)

	return

# send discover, wait for reply
discover = dhcp_discover()

log.info  ("Send DHCP discover")
log.debug ("Source MAC %s", localmac)

sendp (discover, iface = interface, count = 1, verbose = 0)

sniff (filter="udp and (port 67 or port 68)",
	   prn = handle_dhcp_packet,
	   iface = interface,
	   timeout =15)

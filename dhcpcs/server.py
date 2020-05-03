#!/usr/bin/env python

# Scapy based DHCP client

from scapy.all import *
from sys import *
import logging as log
from itertools import count

#configuration
interface = 'enx00e04c70232e'
ServerMac = RandMAC (template="00:a8:3f")
ServerIp = '192.168.1.1'
ClientIp = '192.168.1.20'
Mask = '255.255.255.0'
DisCount = count (1) # :)

log.basicConfig(stream=sys.stdout, level=logging.DEBUG)

log.addLevelName(logging.DEBUG, "\033[1;33m[?]\033[1;0m")
log.addLevelName(logging.INFO,  "\033[1;35m[#]\033[1;0m")

scapy.all.conf.checkIPaddr = False

def dhcp_offer(discover_packet):
    Eth   = Ether(src=ServerMac, dst=discover_packet.src)
    Ip    = IP(src=ServerIp, dst=ClientIp)
    Udp   = UDP(sport=67, dport=68)

    Bootp = BOOTP (chaddr=discover_packet.src,
                   yiaddr=ClientIp,
                   siaddr=ServerIp,
                   xid=discover_packet.xid)

    Dhcp  = DHCP(options=[("message-type", "offer"),
                          ('server_id', ServerIp),
                          ('subnet_mask', Mask),
                           "end"])

    dhcp_offer = Eth / Ip / Udp / Bootp / Dhcp
    return dhcp_offer

def dhcp_ask(request_packet):

    return dhcp_ask

def handle_dhcp_packet(packet):

    if packet[DHCP] and packet[DHCP].options[0][1] == 1: # discover
        log.info (" (%d) New DHCP discover", next(DisCount))
        log.debug ("Transaction ID 0x%x", packet.xid)
        log.debug ("Source MAC %s", packet.src)
        sendp(dhcp_offer(packet), iface = interface, count=1, verbose = 0)
        log.info (" --- Send DHCP offer")

    if packet[DHCP] and packet[DHCP].options[0][1] == 3: # request
        log.info ("New DHCP request")

    return

log.info ("Start DHCP server")

sniff(filter="udp and (port 67 or port 68)",
      prn=handle_dhcp_packet,
      iface = interface)

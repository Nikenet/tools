#! /usr/bin/env python3
from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3,IGMPv3mq,IGMPv3gr

pack = Ether(src="de:ad:be:ef:00:01")/ IP(src="172.10.1.2",dst="224.0.0.22",ttl=1)/ IGMPv3(type=0x22)/ IGMPv3gr(rtype=2,srcaddrs=['225.0.0.5'])
pack.show()
sendp(pack, iface="enp1s0")
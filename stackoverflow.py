from scapy.all import *

# IGMPv3 constants (RFC 3376)
IGMP3_REPORT_TYPE        = 0x22
IGMP3_RESERVED           = 0x0
IGMP3_MODE_IS_INCLUDE    = 0x1
IGMP3_MODE_IS_EXCLUDE    = 0x2
IGMP3_CHANGE_TO_INCLUDE  = 0x3
IGMP3_CHANGE_TO_EXCLUDE  = 0x4
IGMP3_ALLOW_NEW_SOURCES  = 0x5
IGMP3_BLOCK_NEW_SOURCES  = 0x6
IGMP3_MULTICAST_ADDRESS  = "224.0.0.22"
IGMP3_AUX_LEN            = 0x0

# variables
number_of_groups         = 1
number_of_sources        = 1
group_address            = "224.1.1.1"
group_source_address     = "192.168.0.101"
src_mac_address          = "c8:3a:35:d2:02:0b"
src_ip_address           = "192.168.0.1"
packet_ttl               = 1
router_alert             = "\x94\x04\x00\x00"
number_of_groups         = 250

# IGMPv3 report with 1 group
class IGMP3(Packet):
    name = "IGMP3"
    fields_desc = [
                   ByteField("type", IGMP3_REPORT_TYPE),
                   ByteField("reserved", IGMP3_RESERVED),
                   XShortField("chksum", None),
                   XShortField("reserved", IGMP3_RESERVED),
                   XShortField("ngroups", number_of_groups),
                   ByteField("rtype", IGMP3_CHANGE_TO_INCLUDE),
                   ByteField("auxlen", IGMP3_AUX_LEN),
                   XShortField("nsources", number_of_sources),
                   IPField("gaddr", group_address),
                   IPField("srcaddr", group_source_address)
                  ]
    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2] + chr(ck >> 8) + chr(ck & 0xff) + p[4:]
        return p

bind_layers(IP, IGMP3, frag=0, proto=2)

# generate reports for the specified number of groups
for i in range(number_of_groups):
    p = Ether(src=src_mac_address)/IP(src=src_ip_address, dst=IGMP3_MULTICAST_ADDRESS, ttl=packet_ttl, options=router_alert)/IGMP3(gaddr="224.1.4." + str(i + 1))
    sendp(p, iface="enp3s0", verbose=0, loop=0)

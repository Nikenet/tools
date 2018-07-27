from scapy.all import *
from sys import *
import argparse, socket, fcntl

parser = argparse.ArgumentParser(description='TCP syn 80/422 (HTTP/S) trafic generator')
parser.add_argument('iface', type=str)
args = parser.parse_args()

def getmac(interface):
	try:
		mac = open('/sys/class/net/' + args.iface + '/address').readline()
	except:
		mac = "00:00:00:00:00:00"
	return mac[0:17]

def getip(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', interface[:15])
    )[20:24])


http_packet  = \
	  Ether(src = getmac(args.iface), dst = RandMAC()) \
	/ IP(src = getip(args.iface) , dst = RandIP()) \
	/ TCP(sport = 12464, dport = 80, flags="S", seq=12345)


https_packet = \
	  Ether(src = getmac(args.iface), dst = RandMAC()) \
	/ IP(src = getip(args.iface) , dst = RandIP()) \
	/ TCP(sport = 12465, dport = 433, flags="S", seq=12345)

http_packet.show()

try:
	while True:
		time.sleep(1)
		sendp(http_packet,  iface = args.iface , verbose = 0)
		sendp(https_packet, iface = args.iface , verbose = 0)

except KeyboardInterrupt:
    print "\rInterrupted by user"
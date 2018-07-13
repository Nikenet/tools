import argparse
from socket import *
from struct import *
from md5 import md5

print "     _       _     _                  _ _            _   "
print "  __| | ___ | |_  / | __  __      ___| (_) ___ _ __ | |_ "
print " / _` |/ _ \| __| | | \ \/ /____ / __| | |/ _ \ '_ \| __|"
print "| (_| | (_) | |_  | |  >  <_____| (__| | |  __/ | | | |_ "
print " \__,_|\___/ \__| |_| /_/\_\     \___|_|_|\___|_| |_|\__|"
print ""

parser = argparse.ArgumentParser(description='Implementation of 802.1x client')
parser.add_argument('iface', type=str)
parser.add_argument('username', type=str)
parser.add_argument('password', type=str)
parser.add_argument('SrcMAC', type=str)
args = parser.parse_args()

ETHERTYPE_PAE = 0x888e
PAE_GROUP_ADDR = "\x01\x80\xc2\x00\x00\x03"

EAPOL_VERSION = 1
EAPOL_EAPPACKET = 0
EAPOL_START = 1
EAPOL_LOGOFF = 2
EAPOL_KEY = 3
EAPOL_ASF = 4

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

EAP_TYPE_ID = 1
EAP_TYPE_MD5 = 4

def EAPOL(type, payload=""):
    return pack("!BBH", EAPOL_VERSION, type, len(payload))+payload

def EAP(code, id, type=0, data=""):
    if code in [EAP_SUCCESS, EAP_FAILURE]:
        return pack("!BBH", code, id, 4)
    else:
        return pack("!BBHB", code, id, 5+len(data), type)+data

def ethernet_header(src, dst, type):
    return dst+src+pack("!H",type)

s=socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))
s.bind((args.iface, ETHERTYPE_PAE))

llhead=ethernet_header(args.SrcMAC.replace(':', '').decode('hex'), PAE_GROUP_ADDR, ETHERTYPE_PAE)

print "--> Sent EAPOL Start"
s.send(llhead+EAPOL(EAPOL_START))

try:
    while 1:
        p = s.recv(1600)[14:]
        vers,type,eapollen  = unpack("!BBH",p[:4])
        if type == EAPOL_EAPPACKET:
            code, id, eaplen = unpack("!BBH", p[4:8])
            if code == EAP_SUCCESS:
                print "Got EAP Success"
                exit()
            elif code == EAP_FAILURE:
                print "Got EAP Failure"
                exit()
            elif code == EAP_RESPONSE:
                print "?? Got EAP Response"
            elif code == EAP_REQUEST:
                reqtype = unpack("!B", p[8:9])[0]
                reqdata = p[9:4+eaplen]
                if reqtype == EAP_TYPE_ID:
                    print "Got EAP Request for identity"
                    s.send(llhead + EAPOL(EAPOL_EAPPACKET, EAP(EAP_RESPONSE, id, reqtype, args.username)))
                    print "--> Sent EAP response with identity = [%s]" % args.username
                elif reqtype == EAP_TYPE_MD5:
                    print "Got EAP Request for MD5 challenge"
                    challenge=pack("!B",id) + args.password + reqdata[1:]
                    resp=md5(challenge).digest()
                    resp=chr(len(resp))+resp
                    s.send(llhead + EAPOL(EAPOL_EAPPACKET, EAP(EAP_RESPONSE, id, reqtype, resp)))
                    print "--> Send EAP response with MD5 challenge"
                else:
                    print "?? Got unknown Request type (%i)" % reqtype
                    exit()
            else:
                print "?? Got unknown EAP code (%i)" % code
                exit()
        else:
            print "Got EAPOL type %i" % type
            exit()

except KeyboardInterrupt:
    print "\rInterrupted by user"
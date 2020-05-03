#!/usr/bin/env python3

from scapy.config import *
conf.use_pcap = True
conf.sniff_promisc=True
conf.checkIPaddr = False
from scapy.all import *
from multiprocessing import Process
import random
import subprocess
import argparse
import getch
import os

def createParser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--iface', type=str, default='enp1s0', help='To select interface, default=enp2s0', choices=os.listdir('/sys/class/net/'))
    parser.add_argument('-is', '--iface_server', type=str, default='enp2s0', help='To select server interface, default=enp3s0', choices=os.listdir('/sys/class/net/'))
    parser.add_argument('-v', '--vlan', type=int, default=None, help='To select vlan interface, default=None')
    parser.add_argument('-u', '--unicast', action="store_true")
    return parser


class HOST:
    def __init__(self, iface, unicast=False):
        self.iface = iface
        self.vlan = None
        self.unicast = unicast
        self.host_info = {'message_type': '',
                          'host_mac': str(RandMAC('00:00:00:*')),
                          'fake_host_mac': str(RandMAC('00:00:00:*')),
                          'vendor_id': b'TEST_DEVICE',
                          'host_ip': '',
                          'flags': 0x0000 if self.unicast else 0x8000,
                          'fake_host_ip': str(RandIP('10.0.*.*')),
                          'server_mac': '',
                          'server_id': '',
                          'relay_ip': '',
                          'session_id': random.randint(0, 4294967295),
                          't_received': 0,
                          't_updated': 0,
                          'lease_time': 0,
                          'iface': self.iface,
                          'vlan': self.vlan
                          }
        self.pktboot = Ether(src=self.host_info['host_mac'], dst='ff:ff:ff:ff:ff:ff') / \
                       IP(src='0.0.0.0', dst='255.255.255.255') / \
                       UDP(sport=68, dport=67) / \
                       BOOTP(flags=self.host_info['flags'],
                             xid=self.host_info['session_id'],
                             chaddr=mac2str(self.host_info['host_mac']))

    def replace_mac(self, *args):
        if not args:
            self.host_info = {'message_type': '',
                              'host_mac': str(RandMAC('00:00:00:*')),
                              'vendor_id': b'TEST_DEVICE',
                              'host_ip': '',
                              'flags': 0x0000 if self.unicast else 0x8000,
                              'server_mac': '',
                              'server_id': '',
                              'relay_ip': '',
                              'session_id': random.randint(0, 4294967295),
                              't_received': '',
                              't_updated': '',
                              'lease_time': '',
                              'iface': self.iface,
                              'vlan': self.vlan
                              }
            self.pktboot = Ether(src=self.host_info['host_mac'], dst='ff:ff:ff:ff:ff:ff') / \
                           IP(src='0.0.0.0', dst='255.255.255.255') / \
                           UDP(sport=68, dport=67) / \
                           BOOTP(flags=self.host_info['flags'],
                                 xid=self.host_info['session_id'],
                                 chaddr=mac2str(self.host_info['host_mac']))

        else:
            if args[0]:
                self.host_info['host_mac'] = {'message_type': '',
                                              'host_mac': str(RandMAC(args[0])),
                                              'vendor_id': b'TEST_DEVICE',
                                               'host_ip': '',
                                              'flags': 0x0000 if self.unicast else 0x8000,
                                              'server_mac': '',
                                               'server_id': '',
                                               'relay_ip': '',
                                               'session_id': random.randint(0, 4294967295),
                                               't_received': '',
                                               't_updated': '',
                                               'lease_time': '',
                                               'iface': self.iface,
                                               'vlan': self.vlan
                                               }
                self.pktboot = Ether(src=self.host_info['host_mac'], dst='ff:ff:ff:ff:ff:ff') / \
                               IP(src='0.0.0.0', dst='255.255.255.255') / \
                               UDP(sport=68, dport=67) / \
                               BOOTP(flags=self.host_info['flags'],
                                     xid=self.host_info['session_id'],
                                     chaddr=mac2str(self.host_info['host_mac']))

    def print_host_info(self):
        print(self.host_info)

    def send_discover(self, *args):
        discover = DHCP(options=[('message-type', 1),
                                 ('client_id', b'\x01' + mac2str(self.host_info['host_mac'])),
                                 ('vendor_class_id', self.host_info['vendor_id']),
                                 'end'])
        offer = srp1(self.pktboot/discover, timeout=2, iface=self.iface, verbose=False)
        if offer:
            self.host_info['message_type'] = 'offer'
            self.host_info['host_ip'] = offer[BOOTP].yiaddr
            self.host_info['server_mac'] = offer[Ether].src
            self.host_info['server_id'] = self.getval(offer[DHCP].options, 'server_id')
            self.host_info['relay_ip'] = offer[BOOTP].giaddr
            self.host_info['session_id'] = offer[BOOTP].xid
            self.host_info['t_received'] = int(time.time())
            self.host_info['t_updated'] = int(time.time())
            self.host_info['lease_time'] = self.getval(offer[DHCP].options, 'lease_time')
            offer[Ether].src = self.host_info['host_mac']
            # sendp(offer, iface=self.iface, verbose=False)
            return True
        else:
            return False
            
    def send_request(self, *args):
        self.send_discover()
        if self.host_info['message_type'] == 'offer':
            request = DHCP(options=[('message-type', 3),
                                    ('server_id', self.host_info['server_id']),
                                    ('client_id', (b'\x01' + mac2str(self.host_info['host_mac']))),
                                    ('requested_addr', self.host_info['host_ip']),
                                    ('vendor_class_id', self.host_info['vendor_id']),
                                    'end'])
            self.pktboot[BOOTP].secs = int(time.time()) - self.host_info['t_received']
            ack = srp1(self.pktboot/request, timeout=2, iface=self.iface, verbose=False)
            if ack:
                if self.getval(ack[DHCP].options, 'message-type') == 6:
                    print('Server NAK return. Reason: ',
                          (self.getval(ack[DHCP].options, 'error_message')).decode())
                    return False
                elif self.getval(ack[DHCP].options, 'message-type') == 5:
                    self.host_info['message_type'] = 'ack'
                    self.host_info['t_updated'] = int(time.time())
                    return True
        else:
            return False

    def send_update(self):
        pktboot = Ether(src=self.host_info['host_mac'], dst=self.host_info['server_mac']) / \
                  IP(src=self.host_info['host_ip'], dst=self.host_info['server_id']) / \
                  UDP(sport=68, dport=67) / \
                  BOOTP(chaddr=mac2str(self.host_info['host_mac']),
                        ciaddr=self.host_info['host_ip'],
                        yiaddr=self.host_info['host_ip'],
                        flags=self.host_info['flags'],
                        secs=int(time.time()) - self.host_info['t_received'],
                        xid=self.host_info['session_id'])
        request = DHCP(options=[('message-type', 3),
                                ('vendor_class_id', self.host_info['vendor_id']),
                                ('client_id', (b'\x01' + mac2str(self.host_info['host_mac']))),
                                'end'])
        # arp_sender = Process(target=self.send_arp)
        # arp_sender.start()
        ack = srp1(pktboot/request, timeout=3, iface=self.iface, verbose=False)
        # arp_sender.join()
        if ack:
            if self.getval(ack[DHCP].options, 'message-type') == 6:
                print('Server NAK return for update request. Reason:',
                      (self.getval(ack[DHCP].options, 'error_message')).decode())
                return False
            self.host_info['t_updated'] = int(time.time())
            self.host_info['lease_time'] = self.getval(ack[DHCP].options, 'lease_time')
            return True
        else:
            return False

    def send_release(self):
        if self.host_info['host_ip']:
            pktboot = Ether(src=self.host_info['host_mac'], dst=self.host_info['server_mac']) / \
                      IP(src=self.host_info['host_ip'], dst=self.host_info['server_id']) / \
                      UDP(sport=68, dport=67) / \
                      BOOTP(chaddr=mac2str(self.host_info['host_mac']),
                            ciaddr=self.host_info['host_ip'],
                            flags=self.host_info['flags'],
                            secs=int(time.time()) - self.host_info['t_received'],
                            xid=self.host_info['session_id'])
            release = DHCP(options=[('message-type', 7),
                                    ('vendor_class_id', self.host_info['vendor_id']),
                                    ('client_id', (b'\x01' + mac2str(self.host_info['host_mac']))),
                                    'end'])
            sendp(pktboot/release, iface=self.iface, verbose=False)

    def getval(self, option_list, get_option):
        for option in option_list:
            if type(option) is tuple:
                if option[0] == get_option:
                    return option[1]
        return None

    def send_arp(self):
        sniffer = AsyncSniffer(filter='arp[24:4] == {}'.format(int(socket.inet_aton(self.host_info['host_ip']).hex(), 16)),
                                                                    count=1,
                                                                    iface=self.iface,
                                                                    timeout=5)
        sniffer.start()
        sniffer.join()
        if sniffer.results:
            pkt = sniffer.results[0]
            sendp(Ether(src=self.host_info['host_mac'], dst=self.host_info['server_mac'])/
                  ARP(op = 2,
                      hwsrc=self.host_info['host_mac'],
                      hwdst=pkt[ARP].hwsrc,
                      psrc=self.host_info['host_ip'],
                      pdst=pkt[ARP].psrc), iface=self.iface, verbose=False)

    def send_pkts(self, proto='IP', pkt=1):
        arp_req_list = {1: Ether(src=self.host_info['host_mac'], dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['host_ip'], hwdst='ff:ff:ff:ff:ff:ff', pdst=self.host_info['server_id']),    # корректный arp-запрос
                        2: Ether(src=self.host_info['host_mac'], dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=self.host_info['fake_host_mac'], psrc=self.host_info['host_ip'], hwdst='ff:ff:ff:ff:ff:ff', pdst=self.host_info['server_id']),         # некорректный hwsrc
                        3: Ether(src=self.host_info['host_mac'], dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['fake_host_ip'], hwdst='ff:ff:ff:ff:ff:ff', pdst=self.host_info['server_id']),           # некорректный psrc
                        4: Ether(src=self.host_info['fake_host_mac'], dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['host_ip'], hwdst='ff:ff:ff:ff:ff:ff', pdst=self.host_info['server_id']),         # некорректный eth src
                        5: Ether(src=self.host_info['host_mac'], dst=self.host_info['fake_host_mac']) / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['host_ip'], hwdst='ff:ff:ff:ff:ff:ff', pdst=self.host_info['server_id']),  # некорректный eth dst
                        6: Ether(src=self.host_info['host_mac'], dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['host_ip'], hwdst='ff:ff:ff:ff:ff:ff', pdst='232.0.0.1'),            # некорректный pdst
                        }
        arp_rep_list = {1: Ether(src=self.host_info['host_mac'], dst=self.host_info['server_mac']) / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['host_ip'], hwdst=self.host_info['server_mac'], pdst=self.host_info['server_id'], op=2),  # корректный arp-ответ
                        2: Ether(src=self.host_info['host_mac'], dst=self.host_info['server_mac']) / ARP(hwsrc=self.host_info['fake_host_mac'], psrc=self.host_info['host_ip'], hwdst=self.host_info['server_mac'], pdst=self.host_info['server_id'], op=2),       # некорректный hwsrc
                        3: Ether(src=self.host_info['host_mac'], dst=self.host_info['server_mac']) / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['fake_host_ip'], hwdst=self.host_info['server_mac'], pdst=self.host_info['server_id'], op=2),         # некорректный psrc
                        4: Ether(src=self.host_info['fake_host_mac'], dst=self.host_info['server_mac']) / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['host_ip'], hwdst=self.host_info['server_mac'], pdst=self.host_info['server_id'], op=2),       # некорректный eth src
                        5: Ether(src=self.host_info['host_mac'], dst=self.host_info['fake_host_mac']) / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['host_ip'], hwdst=self.host_info['server_mac'], pdst=self.host_info['server_id'], op=2),         # некорректный eth dst
                        6: Ether(src=self.host_info['host_mac'], dst=self.host_info['server_mac']) / ARP(hwsrc=self.host_info['host_mac'], psrc=self.host_info['host_ip'], hwdst=self.host_info['server_mac'], pdst='232.0.0.1', op=2),          # некорректный pdst
                        }
        ip_list = {1: Ether(src=self.host_info['host_mac'], dst=self.host_info['server_mac']) / IP(src=self.host_info['host_ip'], dst=self.host_info['server_id'])/('a'*500),          # некорректный pdst
                   2: Ether(src=self.host_info['host_mac'], dst=self.host_info['server_mac']) / IP(src=self.host_info['fake_host_ip'], dst=self.host_info['server_id'])/('a'*500)}

        if proto == 'ARP_REQ':
            if 1 <= pkt < 7:
                sendp(arp_req_list[pkt], iface=self.iface, verbose=False)
            elif pkt == 7:
                for i in arp_req_list:
                    sendp(arp_req_list[i], iface=self.iface, verbose=False)
            else:
                pass
        elif proto == 'ARP_REP':
            if 1 <= pkt < 7:
                sendp(arp_rep_list[pkt], iface=self.iface, verbose=False)
            elif pkt == 7:
                for i in arp_rep_list:
                    sendp(arp_rep_list[i], iface=self.iface, verbose=False)
            else:
                pass
        elif proto == 'IP':
            if 1 <= pkt < 3:
                sendp(ip_list[pkt], iface=self.iface, verbose=False)
            elif pkt == 3:
                for i in ip_list:
                    sendp(ip_list[i], iface=self.iface, verbose=False)
            else:
                pass
        else:
            pass

    def get_op82(self, server_iface):
        sniffer_on_server = AsyncSniffer(filter='udp port 67 and (ether host {} or ether host {})'.format(self.host_info['host_mac'], self.host_info['server_mac']),
                                stop_filter=lambda x: x.haslayer(DHCP) and self.getval(x[DHCP].options, 'message-type') == 7,
                                iface={server_iface: 'Server'},
                                timeout=5)
        sniffer_on_client = AsyncSniffer(filter='udp port 67 and (ether host {} or ether host {})'.format(self.host_info['host_mac'], self.host_info['server_mac']),
                                stop_filter=lambda x: x.haslayer(DHCP) and self.getval(x[DHCP].options, 'message-type') == 7,
                                iface={self.iface: 'Client'},
                                timeout=5)

        sniffer_on_server.start()
        sniffer_on_client.start()
        time.sleep(0.1)
        self.send_request()
        self.send_update()
        self.send_release()
        sniffer_on_server.join()
        sniffer_on_client.join()
        if sniffer_on_server.results:
            print('==================== Packets on server interface =============================')
            for pkt in sniffer_on_server.results:
                if BOOTP in pkt:
                    option82 = self.getval(pkt[DHCP].options, 'relay_agent_Information')
                    message_type = self.getval(pkt[DHCP].options, 'message-type')
                    if message_type == 1: print('Discover:')
                    elif message_type == 2: print('Offer:')
                    elif message_type == 3: print('Request:')
                    elif message_type == 5: print('Ack:')
                    elif message_type == 6: print('Nak:')
                    elif message_type == 7: print('Release:')
                    if option82:
                        suboptions = self.parse_option82(option82)
                        print('    Option 82 Circuit_ID: ', suboptions['CircuitID'], '[', len(suboptions['CircuitID']), ']')
                        print('    Option 82 Remote_ID : ', suboptions['RemoteID'], '[', len(suboptions['RemoteID']), ']')
                    else:
                        print('    Option 82 not found')
        if sniffer_on_client.results:
            print('==================== Packets on client interface =============================')
            for pkt in sniffer_on_client.results:
                if BOOTP in pkt:
                    option82 = self.getval(pkt[DHCP].options, 'relay_agent_Information')
                    message_type = self.getval(pkt[DHCP].options, 'message-type')
                    if message_type == 1: print('Discover:')
                    elif message_type == 2: print('Offer:')
                    elif message_type == 3: print('Request:')
                    elif message_type == 5: print('Ack:')
                    elif message_type == 6: print('Nak:')
                    elif message_type == 7: print('Release:')
                    if option82:
                        suboptions = self.parse_option82(option82)
                        print('    Option 82 Circuit_ID: ', suboptions['CircuitID'], '[', len(suboptions['CircuitID']), ']')
                        print('    Option 82 Remote_ID : ', suboptions['RemoteID'], '[', len(suboptions['RemoteID']), ']')
                    else:
                        print('    Option 82 not found')

    def parse_option82(self, option):
        suboptions = {'CircuitID': None, 'RemoteID': None}
        suboptions['CircuitID'] = option[2:2+option[1]]
        suboptions['RemoteID'] = option[4+option[1]:]
        return suboptions

class MANY_HOST(HOST):
    def __init__(self, iface, unicast=False):
        super().__init__(iface, unicast=unicast)
        self.host_list = {}
        pass

    def host_spam(self, count):
        try:
            for i in range(1, count+1):
                if self.send_request():
                    self.host_list.update({i: self.host_info})
                    print('{:3} {:17} received {:15}'.format(i,
                                                             self.host_info['host_mac'],
                                                             self.host_info['host_ip']))
                    self.replace_mac()
                else:
                    print('Address not received, continue...')
        except KeyboardInterrupt:
            pass

    def repeat_host_list(self):
        try:
            for i in self.host_list:
                self.host_info = self.host_list[i]
                if self.send_request():
                    self.host_list.update({i: self.host_info})
                    print('{:3} {:17} received {:15}'.format(i,
                                                             self.host_info['host_mac'],
                                                             self.host_info['host_ip']))
                else:
                    print('Address not received, continue...')
        except KeyboardInterrupt:
            pass


    def print_host_list(self):
        for i in self.host_list:
            print('{:3} {:17} received {:15}'.format(i,
                                                     self.host_list[i]['host_mac'],
                                                     self.host_list[i]['host_ip']))


def get_cmd():
    try:
        return getch.getch()
    except OverflowError:
        return None


def check_vlan(func):
    def checker(iface, vlan):
        for root, dirs, files in os.walk('/proc/net/vlan'):
            for name in files:
                f_src = os.path.join(root, name)
                f = open(f_src).read()
                if re.search(r'VID: *{}'.format(vlan), f) and re.search(r'Device: *{}'.format(iface), f):
                    return name
            return func(iface, vlan)
    return checker


@check_vlan
def create_ifvlan(iface, vlan):
    ifname = 'sub{}{}'.format(iface, vlan)
    subprocess.call(['ip', 'link', 'add', 'link', iface, 'name', ifname, 'type', 'vlan', 'id', str(vlan)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
    subprocess.call(
        ['ip', 'link', 'set', ifname, 'up'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    subprocess.call(
        ['ip', 'link', 'set', ifname, 'promisc', 'on'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    return ifname



def delete_ifvlan(iface):
    subprocess.call(['ip', 'link', 'delete', iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)

if __name__ == '__main__':
    parser = createParser()
    params = parser.parse_args(sys.argv[1:])
    if params.vlan:
        iface = create_ifvlan(params.iface, params.vlan)
    else:
        iface = params.iface
    print('END: ',iface)
    off = MANY_HOST(iface, unicast=params.unicast)
    msg = ''
    try:
        while True:
            os.system('clear')
            print('What the next?\n\r ',
                  '1) Spawn new mac\n\r ',
                  '2) Send discover\n\r ',
                  '3) Send request for last mac\n\r ',
                  '4) Send update for last mac\n\r ',
                  '5) Send release for last mac\n\r ',
                  '6) ARP/IP Guard \n\r ',
                  '7) Some number of random hosts \n\r ',
                  '8) Print Host Info \n\r ',
                  '9) Print Op82 \n\r ',
                  '0) Exit\n\r',
                  '-'*100, '\n\r',
                  msg, '\n\r')
            cmd = get_cmd()
            if cmd == '1':
                off.replace_mac()
                msg = 'HW Changed to {}'.format(off.host_info['host_mac'])
            elif cmd == '2':
                if off.send_discover():
                    msg = 'IP new candidate {:17} {:15}'.format(off.host_info['host_mac'],
                                                                off.host_info['host_ip'])
                else:
                    msg = 'Server is not available'
            elif cmd == '3':
                if off.send_request():
                    msg = 'IP received {:17} {:15}'.format(off.host_info['host_mac'],
                                                           off.host_info['host_ip'])
                else:
                    msg = 'Server is not available'
            elif cmd == '4':
                if not off.host_info['message_type'] == 'ack':
                    msg = 'First received IP for last MAC'
                else:
                    if off.send_update():
                        'IP update {:17} {:15}'.format(off.host_info['host_mac'],
                                                       off.host_info['host_ip'])
                    else:
                        msg = 'Server is not available'

            elif cmd == '5':
                if not off.host_info['message_type'] == 'ack':
                    msg = 'First received IP for last mac'
                else:
                    msg = 'IP release {:17} {:15}'.format(off.host_info['host_mac'],
                                                          off.host_info['host_ip'])
                    off.send_release()
            elif cmd == '6':
                if off.host_info['message_type'] == 'ack':
                    while True:
                        os.system('clear')
                        print('What the next?\n\r'
                              '1) Send ARP Request\n\r'
                              '2) Send ARP Reply\n\r'
                              '3) Send IP\n\r'
                              '0) Exit'
                              )
                        cmd = get_cmd()
                        if cmd == '1':
                            while True:
                                os.system('clear')
                                print('What the next?\n\r'
                                      '1) Send correct ARP Request\n\r'
                                      '2) Send incorrect ARP Request (hwsrc)\n\r'
                                      '3) Send incorrect ARP Request (psrc)\n\r'
                                      '4) Send incorrect ARP Request (eth src)\n\r'
                                      '5) Send incorrect ARP Request (eth dst)\n\r'
                                      '6) Send incorrect ARP Request (pdst)\n\r'
                                      '7) All\n\r'
                                      '0) Exit'
                                      )
                                cmd = get_cmd()
                                if cmd == '0':
                                    break
                                off.send_pkts(proto='ARP_REQ', pkt=int(cmd))
                        elif cmd == '2':
                            while True:
                                os.system('clear')
                                print('What the next?\n\r'
                                      '1) Send correct ARP Reply\n\r'
                                      '2) Send incorrect ARP Reply (hwsrc)\n\r'
                                      '3) Send incorrect ARP Reply (psrc)\n\r'
                                      '4) Send incorrect ARP Reply (eth src)\n\r'
                                      '5) Send incorrect ARP Reply (eth dst)\n\r'
                                      '6) Send incorrect ARP Reply (pdst)\n\r'
                                      '7) All\n\r'
                                      '0) Exit'
                                      )
                                cmd = get_cmd()
                                if cmd == '0':
                                    break
                                off.send_pkts(proto='ARP_REP', pkt=int(cmd))
                        elif cmd == '3':
                            while True:
                                os.system('clear')
                                print('What the next?\n\r'
                                      '1) Send correct IP Pkt\n\r'
                                      '2) Send incorrect IP Pkt (ip_src)\n\r'
                                      '3) Send all IP Pkts\n\r'
                                      '0) Exit'
                                      )
                                cmd = get_cmd()
                                if cmd == '0':
                                    break
                                off.send_pkts(proto='IP', pkt=int(cmd))
                        elif cmd == '0':
                            break
                else:
                    msg = 'First spawn new MAC'
                    continue

            elif cmd == '7':
                while True:
                    os.system('clear')
                    count = input('Enter the number of DHCP Hosts: ')
                    off.host_spam(count=int(count))
                    print('What the next? \r\n'
                          '1) Repeat new MAC Pool \r\n'
                          '2) Repeat current MAC Pool \r\n'
                          '0) Exit \r\n')
                    cmd = get_cmd()
                    if cmd == '1':
                        continue
                    elif cmd == '2':
                        while True:
                            os.system('clear')
                            off.repeat_host_list()
                            print('What the next? \r\n'
                                  '1) Repeat new MAC Pool \r\n'
                                  '2) Repeat current MAC Pool \r\n'
                                  '0) Exit \r\n')
                            cmd = get_cmd()
                            if cmd == '1':
                                break
                            elif cmd == '2':
                                continue
                            elif cmd == '0':
                                break
                            else:
                                print('Incorrect')
                                continue
                    elif cmd == '0':
                        break
                    else:
                        print('Incorrect')
                        continue
            elif cmd == '8':
                off.print_host_info()
                print('What the next? \r\n'
                      '1) Continue \r\n'
                      '0) Exit \r\n')
                cmd = get_cmd()
                if cmd == '1':
                    continue
                elif cmd == '0':
                    break
                else:
                    print('Incorrect')
                    continue

            elif cmd == '9':
                off.get_op82(params.iface_server)
                print('What the next? \r\n'
                      '1) Continue \r\n'
                      '0) Exit \r\n')
                cmd = get_cmd()
                if cmd == '1':
                    continue
                elif cmd == '0':
                    break
                else:
                    print('Incorrect')
                    continue
            elif cmd == '0':
                exit(0)
            else:
                msg = 'Incorrect'
                continue
    except KeyboardInterrupt:
        exit(0)
    finally:
        if params.vlan:
            delete_ifvlan(iface)

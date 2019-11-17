from scapy.all import *
import sys

sys.path.append("..")
from common.arp.arp_helper import get_mac_addr


class PackageForwarder:

    def __init__(self, iface_, ipDst):
        self.iface = iface_
        self.ipDst = ipDst
        self.macDst = get_mac_addr(iface_, ipDst)

    def get_mac_dst(self):
        return self.macDst

    def set_mac_dst(self, macDst):
        self.macDst = macDst

    def get_ip_dst(self):
        return self.ipDst

    def set_ip_dst(self, ipDst):
        self.ipDst = ipDst

    def set_interface(self, iface_):
        self.iface = iface_

    def get_interface(self):
        return self.iface

    def ip_packet_sniff(self):
        sniff(iface=self.iface, filter="icmp", prn=lambda x: x.summary())

    def packetHandler(self, pkt):
        if pkt[Ether].type == 0x800:
            if pkt[IP].dst == self.ipDst:
                mpkt = Ether(dst=self.macDst) / IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(
                    dpot=pkt[TCP].dport) / pkt.load
                sendp(pkt, iface=self.iface)

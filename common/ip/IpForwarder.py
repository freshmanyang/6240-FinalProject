
from scapy.all import *

def class PackageForwarder:
    
    def __init__(self,nif,ipDst,macDst):
        self.nif = nif
        self.ipDst = ipDst
        self.macDst = macDst

    def getMacDst(self):
        return self.macDst

    def setMacDst(self,macDst):
        self.macDst = macDst

    def getIpDst(self):
        return self.ipDst

    def setIpDst(self,ipDst):
        self.ipDst = ipDst

    def setNif(self,nif):
        self.nif = nif
    
    def getNif(self):
        return self.nif

    def ip_packet_sniff(interface_name,func):
        sniff(iface=interface_name,filter="tcp",prn=func)

    def packetHandler(self,pkt):
        if pkt[ether].type == 0x800:
            if pkt[IP].dst == self.ipDst:
               mpkt = Ether(dst=self.macDst)/IP(src=pkt[IP].src,dst=pkt[IP].dst)/TCP(dpot=pkt[TCP].dport)/pkt.load
               sendp(pkt,iface=self.nif)

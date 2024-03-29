#!/usr/bin/env python3
import argparse
import sys

sys.path.append("..")
from common.ip.ip_scanner import *
from common.arp.arp_helper import *
from common.ip.IpForwarder import PackageForwarder

if __name__ == '__main__':
    # parse arguments from command line
    parser = argparse.ArgumentParser()
    parser.add_argument("command",
                        help="[scan]: scan live ip address; [spoof]: issue an arp spoofing attack; [sniff]: sniff packets")
    parser.add_argument("-i", help="interface")
    parser.add_argument("-t", help="target ip address")
    parser.add_argument("-v", help="victim ip address")
    args = parser.parse_args()

    if args.command == 'scan' and args.i and (not args.t and not args.v):
        try:
            iface_info = get_interface_info(args.i)
        except:
            print("Invalid interface")
            sys.exit(1)
        else:
            net_addr = get_network_address(iface_info)
            scanner(net_addr, get_ip_count(iface_info["netmask"]))
    elif args.command == 'spoof' and args.i and args.t and args.v:
        try:
            iface_info = get_interface_info(args.i)
        except:
            print("Invalid interface")
            sys.exit(1)
        else:
            spoof(args.i, args.t, args.v)
    elif args.command == 'sniff' and args.i and args.v and not args.t:
        try:
            forwarder = PackageForwarder(args.i, args.v)
        except:
            print("Invalid interface")
            sys.exit(1)
        else:
            forwarder.ip_packet_sniff()
    else:
        print("Invalid arguments")
        sys.exit(1)

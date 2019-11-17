import socket  # for address and netmask convert
import netifaces  # for netmask
import subprocess  # for ping cmd
import re  # for regexp


def get_interface_info(iface_):
    """
        get network information from an interface
        :param iface_: interface
        :return: {ip address, netmask} (json object)
    """
    # get IP address and netmask from interface
    info_ = netifaces.ifaddresses(iface_)
    ip_addr_ = info_[netifaces.AF_INET][0]['addr']
    mac_addr_ = info_[netifaces.AF_LINK][0]['addr']
    netmask_ = info_[netifaces.AF_INET][0]['netmask']
    return {"ip_addr": ip_addr_, "netmask": netmask_, "mac_addr": mac_addr_}


def get_network_address(iface_info_):
    """
        calculate network address based IP address and netmask
        :param iface_info_: {ip address, netmask} (json object)
        :return: netwrok address (string)
    """
    net_addr_b_ = [0] * 4
    ip_addr_b_ = socket.inet_pton(socket.AF_INET, iface_info_["ip_addr"])
    netmask_b_ = socket.inet_pton(socket.AF_INET, iface_info_["netmask"])
    for i in range(4):
        net_addr_b_[i] = ip_addr_b_[i] & netmask_b_[i]
    net_addr_b_ = bytes(net_addr_b_)
    net_addr_ = socket.inet_ntop(socket.AF_INET, net_addr_b_)
    return net_addr_


def get_number_of_1(n):
    """
        get the number of bit which has value 1
        :param n: number
        :return: count of bit 1
    """
    count = 0
    if n <= 0:
        return count
    while (n & 0xffffffff) != 0:
        count += 1
        n = n & (n - 1)  # n = n - 1
    return count


def get_ip_count(netmask_):
    """
        ip total number of valid ip address based on netmask
        :param netmask_: network mask (string)
        :return: count of available ip addresses
    """
    netmask_b_ = socket.inet_pton(socket.AF_INET, netmask_)
    network_prefix_len = 0
    for x in netmask_b_:
        network_prefix_len += get_number_of_1(x)

    host_suffix_len = 32 - network_prefix_len
    count = pow(2, host_suffix_len)
    return count


def get_next_ip_address(addr_int, index=3):
    """
        get the next ip address
        :param addr_int: current ip address(int list)
        :param index: point to the octet
        :return: None
    """
    if index < 0:
        return
    if addr_int[index] == 255:
        addr_int[index] = 0
        get_next_ip_address(addr_int, index - 1)
    else:
        addr_int[index] += 1


def ping(ip_addr_, count, interval, waittime):
    """
        issue ping command to check if an ip address is alive or not
        :param ip_addr_: ip address
        :param count: ping count
        :param interval: time interval between sending two packets
        :param waittime: Mac OS: in milliseconds
                         Linux: in seconds
        :return: Boolean
    """
    cmd = 'ping -c %d -i %f -W %d %s' % (count, interval, waittime, ip_addr_)
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout
    ping_result = str(pipe.read())
    # regx = re.findall('100.0% packet loss', ping_result)  # for MacOS, use 100.0%
    regx = re.findall('100% packet loss', ping_result)  # for linux, use 100%
    if len(regx) == 0:
        return True
    else:
        return False


def scanner(net_addr_, count):
    """
        get the list of available ip addresses
        :param net_addr_: network address(str)
        :param count: count of available ip addresses
        :return: None
    """
    # get int format ip address, start from the network address
    next_addr_int = list(map(int, net_addr_.split('.')))
    for j in range(1, count):
        try:
            get_next_ip_address(next_addr_int)
            # covert ip address from int to string
            next_addr = '.'.join(list(map(str, next_addr_int)))
            # test if ip is alive
            # if ping(next_addr, count=1, interval=0.1, waittime=10): # for Mac
            if ping(next_addr, count=1, interval=0.2, waittime=1):  # for Linux
                print("%s \tstatus: %s" % (next_addr, 'UP'))
            else:
                print("%s \tstatus: %s" % (next_addr, 'DOWN'))
        except KeyboardInterrupt:
            print("\nIP scanner exit")
            exit(0)
    return

# 6240-FinalProject
[Description]
A man-in-the-middle attack tool consists with IP Scanner, ARP Poisoner and Packet Sniffer

[Usage]
- IP Scanner
  
  sudo ./main.py scan -i \<interface\>
  
- ARP Poisoner
  
  sudo ./main.py spoof -i \<interface\> -t \<target IP\> -v \<victim IP\>
  
- Packet Sniffer
  
  sudo ./main.py sniff -i \<interface\> -v \<victim IP\>
 
[Dependency]
- Python3.4 and above
- netifaces
- scapy

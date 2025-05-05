Packet Sniffer

Before running, ensure the wireless interface is renamed to wlan0 and is in monitor mode and the ethernet interface is renamed to enp0s3 and in promiscuous mode

to run Packet Sniffer:
sudo python3 sniffer.py --flags

flags:
  --a ACTIVATE ALL INTERFACES
  --e ACTIVATE ETHERNET INTERFACE
  --w ACTIVATE WIRELESS INTERFACE
  --o file OUTPUT TO file
  --tcp FILTER TCP PACKETS
  --udp FILTER UDP PACKETS
  --arp FILTER ARP PACKETS
  --icmp FILTER ICMP PACKETS
  --icmpv6 FILTER ICMPV6 PACKETS
  --ipv4 FILTER IPV4 PACKETS
  --ipv6 FILTER IPV6 PACKETS
  --ip_src ip  FILTER PACKETS FROM ip
  --ip_dest ip FILTER PACKETS TO ip
  --mac_src mac FILTER PACKETS FROM mac
  --mac_dest mac FILTER PACKETS TO mac

to run custom packet creator:
sudo python3 spoof.py --flags

flags:
  --tcp SEND TCP PACKET
  --udp SEND UDP PACKET
  --ack ADD ACK FLAG
  --psh ADD PSH FLAG
  --urg ADD URG FLAG
  --rst ADD RST FLAG
  --syn ADD SYN FLAG
  --fin ADD FIN FLAG
  --destip ip SEND PACKET TO ip
  --srcip ip PACKET GOING TO BE SENT FROM ip
  --destmac mac SEND PACKET TO mac
  --srcmac mac PACKET GOING TO BE SENT FROM mac

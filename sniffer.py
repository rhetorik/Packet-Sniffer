import sys
import socket
import select
import output
import parser
import argparse
import filter

arg_flags = argparse.ArgumentParser()

arg_flags.add_argument('--a', action='store_true')
arg_flags.add_argument('--e', action='store_true')
arg_flags.add_argument('--w', action='store_true')
arg_flags.add_argument('--o', type=str)
arg_flags.add_argument('--ip_src', type=str)
arg_flags.add_argument('--ip_dest', type=str)
arg_flags.add_argument('--mac_src', type=str)
arg_flags.add_argument('--mac_dest', type=str)
arg_flags.add_argument('--tcp', action='store_true')
arg_flags.add_argument('--udp', action='store_true')
arg_flags.add_argument('--icmp', action='store_true')
arg_flags.add_argument('--icmpv6', action='store_true')
arg_flags.add_argument('--ipv4', action='store_true')
arg_flags.add_argument('--ipv6', action='store_true')
arg_flags.add_argument('--arp', action='store_true')


        


def main():
    eth_sock = None
    wifi_sock = None
    interfaces = [sys.stdin]
    output_file = sys.stdout
    
    myFilter = filter.filter()


    args = arg_flags.parse_args()

    if args.o:
        try:
            output_file = open(args.o, 'w')
            print("Packet Sniffer Log", file=output_file)
        except Exception as e:
            print("Error Opening Log File")
            return
    if args.a:
        try:
            eth_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            eth_sock.bind(('enp0s3', 0))
            wifi_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            wifi_sock.bind(('wlan0', 0))
            interfaces += [eth_sock, wifi_sock]
            print("Sniffing on both Ethernet and Wireless Interfaces", file=output_file)
        except Exception as e:
            print("Error Binding To Interfaces")
            return
    if args.e:
        try:
            eth_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            eth_sock.bind(('enp0s3', 0))
            interfaces += [eth_sock]
            print("Sniffing on Ethernet Interface", file=output_file)
        except Exception as e:
            print("Error Binding To Ethernet Interface")
            return
    if args.w:
        try:
            wifi_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            wifi_sock.bind(('wlan0', 0))
            interfaces += [wifi_sock]
            print("Sniffing on Wireless Interface", file=output_file)
        except Exception as e:
            print("Error Binding To Wireless Interface")
            return
    if args.ip_src:
        try:
            test = socket.inet_aton(args.ip_src) 
            myFilter.ip_src = args.ip_src
            print(f"Filtering packets from {args.ip_src}", file=output_file)
        except socket.error:
            print("ERROR INVALID IP SOURCE")
            return
    if args.ip_dest:
        try:
            test = socket.inet_aton(args.ip_dest)
            myFilter.ip_dest = args.ip_dest
            print(f"Filtering packets going to {args.ip_dest}", file=output_file)
        except socket.error:
            print("ERROR INVALID IP DESTINATION")
            return
    if args.mac_src:
        myFilter.mac_src = args.mac_src
        print(f"Filtering packets from {args.mac_src}", file=output_file)
    if args.mac_dest:
        myFilter.mac_dest = args.mac_dest
        print(f"Filtering packets going to {args.mac_dest}", file=output_file)
    if args.tcp:
        if myFilter.transport_proto[0] == "any":
            myFilter.transport_proto.pop(0)
        myFilter.transport_proto.append("tcp")
        print("Filtering for tcp packets", file=output_file)
    if args.udp:
        if myFilter.transport_proto[0] == "any":
            myFilter.transport_proto.pop(0)
        myFilter.transport_proto.append("udp")
        print("Filtering for udp packets", file=output_file)
    if args.icmp:
        if myFilter.transport_proto[0] == "any":
            myFilter.transport_proto.pop(0)
        myFilter.transport_proto.append("icmp")
        print("Filtering for icmp packets", file=output_file)
    if args.icmpv6:
        if myFilter.transport_proto[0] == "any":
            myFilter.transport_proto.pop(0)
        myFilter.transport_proto.append("icmpv6")
        print("Filtering for icmpv6 packets", file=output_file)
    if args.ipv4:
        if myFilter.network_proto[0] == "any":
            myFilter.network_proto.pop(0)
        myFilter.network_proto.append("ipv4")
        print("Filtering for ipv4 packets", file=output_file)
    if args.ipv6:
        if myFilter.network_proto[0] == "any":
            myFilter.network_proto.pop(0)
        myFilter.network_proto.append("ipv6")
        print("Filtering for ipv6 packets", file=output_file)
    if args.arp:
        if myFilter.network_proto[0] == "any":
            myFilter.network_proto.pop(0)
        myFilter.network_proto.append("arp")
        print("Filtering for arp packets", file=output_file)


    print("Initializing Packet Sniffer", file=output_file) 
    while True:
        r, _, _, = select.select(interfaces, [], [])
        for sock in r:
            if sock == sys.stdin:
                try:
                    data = sys.stdin.readline().strip()
                    if data == "exit":
                        output_file.close()
                        return
                    else:
                        print("UNRECOGNIZED COMMAND: ", data)
                        break
                except Exception:
                    print("ERROR READING FROM STDIN")
                    break

                
            try:
                data, addr = sock.recvfrom(65565)
            except socket.error:
                print("ERROR RECEIVING DATA FROM SOCKET")
                break

            if sock == wifi_sock:
                wifi_header = parser.wifi_unpack(data)
                if wifi_header:
                    output.wifi_header(wifi_header, output_file)


            #Ethernet Frame
            if sock == eth_sock:
                eth_header = parser.eth_unpack(data)
                if eth_header == None:
                    continue
                eth_proto = int(eth_header['proto'], 16)
                
                #802.3 LLC + (Maybe SNAP) 
                if eth_proto < 0x600:
                    ieee_header = parser.IEEE_802_unpack(eth_header['data'])
                    if ieee_header and ieee_header['type'] == "SNAP":
                        eth_proto = ieee_header['pid']
                        eth_proto = int(eth_proto, 16)
                        payload = ieee_header['payload']
                        ip_header = parser.identify_ethertype(eth_proto, payload)
                        if ip_header:
                            if myFilter.verify(eth_header, ip_header, ip_header["transport_header"]):
                                output.frame(eth_header, ieee_header, ip_header, ip_header['transport_header'], output_file)

                        


                    elif ieee_header['type'] == "LLC":
                        if myFilter.verify(eth_header, None, None):
                            output.frame(eth_header, ieee_header, None, None, output_file)

                elif (eth_proto >= 0x600):
                    ip_header = parser.identify_ethertype(eth_proto, eth_header['data'])
                    if ip_header:
                        if myFilter.verify(eth_header, ip_header, ip_header["transport_header"]):
                            output.frame(eth_header, None, ip_header, ip_header['transport_header'], output_file)
                




         
main()



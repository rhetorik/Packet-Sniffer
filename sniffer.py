import sys
import socket
import struct
import select
import output
import parser
import argparse

arg_flags = argparse.ArgumentParser()

arg_flags.add_argument('--a', action='store_true')
arg_flags.add_argument('--e', action='store_true')
arg_flags.add_argument('--w', action='store_true')
arg_flags.add_argument('--o', type=str)
arg_flags.add_argument('--src', type=str)
arg_flags.add_argument('--dest', type=str)
arg_flags.add_argument('--tcp', action='store_true')
arg_flags.add_argument('--udp', action='store_true')


        


def main():
    eth_sock = None
    wifi_sock = None
    interfaces = [sys.stdin]
    output_file = sys.stdout
    src_filter = 'any'
    dest_filter = 'any'
    trans_filter = 'any'


    args = arg_flags.parse_args()

    if args.a:
        try:
            eth_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            eth_sock.bind(('enp0s3', 0))
            wifi_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            wifi_sock.bind(('wlan0', 0))
            interfaces += [eth_sock, wifi_sock]
            print("Sniffing on both Ethernet and Wireless Interfaces")
        except Exception as e:
            print("Error Binding To Interfaces")
            return
    if args.e:
        try:
            eth_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            eth_sock.bind(('enp0s3', 0))
            interfaces += [eth_sock]
            print("Sniffing on Ethernet Interface")
        except Exception as e:
            print("Error Binding To Ethernet Interface")
            return
    if args.w:
        try:
            wifi_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            wifi_sock.bind(('wlan0', 0))
            interfaces += [wifi_sock]
            print("Sniffing on Wireless Interface")
        except Exception as e:
            print("Error Binding To Wireless Interface")
            return
    if args.o:
        try:
            output_file = open(args.o, 'w')
            print("Packet Sniffer Log", file=output_file)
        except Exception as e:
            print("Error Opening Log File")
            return 
    if args.src:
        try:
            test = socket.inet_aton(args.src) 
            src_filter = args.src
        except socket.error:
            print("ERROR INVALID IP SOURCE")
            return
    if args.dest:
        try:
            test = socket.inet_aton(args.dest)
            dest_filter = args.dest
        except socket.error:
            print("ERROR INVALID IP DESTINATION")
            return
    if args.tcp:
        trans_filter = 'tcp'
    if args.udp:
        trans_filter = 'udp'



    print("Initializing Packet Sniffer", file=output_file) 
    while True:
        r, _, _, = select.select(interfaces, [], [])
        for sock in r:
            if sock == sys.stdin:
                try:
                    data = sys.stdin.readline().strip()
                    if data == "exit":
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
                output.wifi_header(wifi_header)


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
                            output.frame(eth_header, ieee_header, ip_header, ip_header['transport_header'], src_filter, dest_filter, trans_filter)

                        


                    elif ieee_header['type'] == "LLC":
                        output.frame(eth_header, ieee_header, None, None, src_filter, dest_filter, trans_filter)

                elif (eth_proto >= 0x600):
                    ip_header = parser.identify_ethertype(eth_proto, eth_header['data'])
                    if ip_header:
                        output.frame(eth_header, None, ip_header, ip_header['transport_header'], src_filter, dest_filter, trans_filter)
                




         
main()


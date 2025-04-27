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


        


def main():
    eth_sock = None
    wifi_sock = None
    interfaces = [sys.stdin]
    output_file = sys.stdout
    src = 'any'
    dest = 'any'


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
            src = socket.inet_aton(args.src) 
        except socket.error:
            print("ERROR INVALID IP SOURCE")
            return
    if args.dest:
        try:
            dest = socket.inet_aton(args.dest)
        except socket.error:
            print("ERROR INVALID IP DESTINATION")
            return



    print("Initializing Packet Sniffer", file=output_file) 
    while True:
        r, _, _, = select.select(interfaces, [], [])
        for sock in r:
            if sock == sys.stdin:
                data = sys.stdin.readline().strip()
                if data == "exit":
                   return
                else:
                    print("UNRECOGNIZED COMMAND: ", data)
                    break
                

            data, addr = sock.recvfrom(65565)
            if sock == wifi_sock:
                wifi_header = parser.wifi_unpack(data)
                #if wifi_header and wifi_header['ftype'] == 2:
                output.wifi_header(wifi_header)


            #Ethernet Frame
            if sock == eth_sock:
                mac_dest, mac_src, eth_proto, payload = parser.eth_unpack(data)
                eth_proto = int(eth_proto, 16)
                output.ethernet_frame(eth_proto, mac_dest, mac_src)
                
                #802.3 LLC + (Maybe SNAP) 
                if eth_proto < 0x600:
                    ieee_header = parser.IEEE_802_unpack(payload)
                    if ieee_header['type'] == "SNAP":
                        output.llc_header(ieee_header['dsap'], ieee_header['ssap'], ieee_header['control'])
                        output.snap_header(ieee_header['oui'], ieee_header['pid'])
                        eth_proto = ieee_header['pid']
                        eth_proto = int(eth_proto, 16)
                        payload = ieee_header['payload']
                        ip_header = parser.identify_ethertype(eth_proto, payload)
                        output.frame(ethernet_header, llc_header, transport_header, src_filter, dest_filter)

                        


                    elif ieee_header['type'] == "LLC":
                        output.llc_header(ieee_header['dsap'], ieee_header['ssap'], ieee_header['control'])

                if (eth_proto > 0x600):
                    parser.identify_ethertype(eth_proto, payload)
                




         
main()


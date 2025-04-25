import sys
import socket
import struct
import select
import output
import parser


def main():
    eth_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    eth_sock.bind(('enp0s3', 0))
    wifi_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    wifi_sock.bind(('wlan0', 0))
    while True:
        r, _, _, = select.select([wifi_sock, eth_sock], [], [])
        for sock in r:
            
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
                        


                    elif ieee_header['type'] == "LLC":
                        output.llc_header(ieee_header['dsap'], ieee_header['ssap'], ieee_header['control'])

                if (eth_proto > 0x600):
                    parser.identify_ethertype(eth_proto, payload)
                




         
main()


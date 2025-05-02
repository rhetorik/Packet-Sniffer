control_frame = {
            7: "Control Wrapper",
            8: "Block ACK REQ",
            9: "Block ACK",
            10: "PS-POLL",
            11: "Request To Send",
            12: "Clear To Send",
            13: "ACK",
            14: "CF-END",
            15: "CF-END + CF-ACK"
        }

def wifi_header(header):
    print("\n802.11, WIFI FRAME:")
    print(f"\tDuration: {header["duration"]} Frame Control Header:")
    print(f"\t\tVersion: {header["version"]} Frame Type: {header["ftype"]} Subtype: {header["subtype"]}")
    print("\t\tFlags:")
    print(f"\t\t\tTo DS: {header["flags"]["to_ds"]} From DS: {header["flags"]["from_ds"]} More Frag: {header["flags"]["more_frag"]} Retry: {header["flags"]["retry"]}")
    print(f"\t\t\tPower Management: {header["flags"]["power_mgmt"]} More Data: {header["flags"]["more_data"]} Protected Frame: {header["flags"]["protected_frame"]} +HTC/Order: {header["flags"]["htc_order"]}")
    if header["flags"]["to_ds"] == 0 and header["flags"]["from_ds"] == 0:
        if header["ftype"] == 1:
            print(f"\t\t{control_frame[header["subtype"]]} Receiver Address: {header["addr_1"]} Transmitter Address: {header["addr_2"]}")
        else:
            if header["addr_1"] == "ff:ff:ff:ff:ff:ff":
                header["addr_1"] = "Broadcast"
            print(f"\t\tDestination: {header["addr_1"]} Source: {header["addr_2"]} BSSID: {header["addr_3"]}")
    elif header["flags"]["to_ds"] == 1 and header["flags"]["from_ds"] == 0:
        print(f"\t\tBSSID: {header["addr_1"]} Source: {header["addr_2"]} Destination: {header["addr_3"]}")
    elif header["flags"]["to_ds"] == 0 and header["flags"]["from_ds"] == 1:
        print(f"\t\tDestination: {header["addr_1"]} BSSID: {header["addr_2"]} Source: {header["addr_3"]}")
    else:
        print(f"\t\tReceiver Address: {header["addr_1"]} Transmitter Address: {header["addr_2"]} Destination: {header["addr_3"]} Source: {header["addr_4"]}")

    

def ethernet_frame(eth_proto, mac_dest, mac_src): 
    print("\nEthernet Frame:")
    print(f"\tDestination: {mac_dest} Source: {mac_src} Protocol: {eth_proto}")

def snap_header(oui, pid):
    print('\tIEEE 802.3 LLC + SNAP HEADER:')
    print(f'OUI: {oui} Protocol ID: {pid}')

def llc_header(dsap, ssap, control):
    print('\tIEEE 802.3 LLC Header:')
    print(f'DSAP: {dsap} SSAP: {ssap} Control: {control}')

def ipv6_header(version, traffic, flow, payload_length, next_header, hop, ip_src, ip_dest):
    print("\tIPv6 PACKET:")
    print(f"\t\tVersion: {version} Traffic Class: {traffic} Flow: {flow}")
    print(f"\t\tPayload Length: {payload_length} Next Header: {next_header} Hop Limit: {hop}")
    print(f"\t\tSOURCE: {ip_src} DEST: {ip_dest}")

def ipv4_header(version, header_length, ttl, ip_src, ip_dest, ip_proto):
    print("\tIPv4 PACKET:")
    print(f"\t\tVersion: {version} Header Length: {header_length} TTL: {ttl}")
    print(f"\t\tSOURCE: {ip_src} DEST: {ip_dest} PROTOCOL: {ip_proto}")

def arp_message(hw_type, p_type, hw_len, p_len, op, sender_mac, sender_ip, target_mac, target_ip):
    print("\tARP:")
    print(f"\t\tHardware Type: {hw_type} Protocol Type: {p_type} Hardware Length: {hw_len} Protocol Length: {p_len}")
    if op == "1" or op == 1:
        print(f"\t\tRequest: who has IP:{target_ip} tell IP:{sender_ip}")
    elif op == "2" or op == 2:
        print(f"\t\tReply: IP:{sender_ip} is at Hardware: {sender_mac}")
    else:
        print("unknown arp type")

def icmpv6_header(icmp_type, code, checksum, data):
    print("\tICMPv6 Packet:")
    print(f"\t\tType: {icmp_type} Code: {code} Checksum: {checksum}")

def icmpv4_packet(icmp_type, code, checksum, data):
    print("\tICMPv4 Packet:")
    print(f"\t\tType: {icmp_type} Code: {code} Checksum: {checksum}")

def tcp_packet(src_port, dest_port, sequence_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data):
    print("\tTCP segment:")
    print(f"\t\tSource Port: {src_port} Destination Port: {dest_port}")
    print(f"\t\tSequence: {sequence_num} Acknowledgement: {ack}")
    print("\t\tFlags:")
    print(f"\t\t\tURG: {flag_urg} ACK: {flag_ack} PSH: {flag_psh} RST: {flag_rst} SYN: {flag_syn} FIN: {flag_fin}")

def udp_packet(src_port, dest_port, length, data):
    print("\tUDP Segment:")
    print(f"\t\tSource Port: {src_port} Destination Port: {dest_port} Length: {length}")

def unknown_packet(data):
    print("\tUnknown Packet Data: ")
    print("\t\t", data.hex())
    
def transport(transport_header):
    if transport_header['type'] == 'tcp':
        tcp_packet(transport_header['src_port'], transport_header['dest_port'], transport_header['sequence_num'], transport_header['ack'], transport_header['flag_urg'], transport_header['flag_ack'], transport_header['flag_psh'], transport_header['flag_rst'], transport_header['flag_syn'], transport_header['flag_fin'], transport_header['data'])
    elif transport_header['type'] == 'udp':
        udp_packet(transport_header['src_port'], transport_header['dest_port'], transport_header['size'], transport_header['data'])
    elif transport_header['type'] == 'icmp':
        icmpv4_packet(transport_header['icmp_type'], transport_header['code'], transport_header['checksum'], transport_header['data'])
    elif transport_header['type'] == 'icmpv6':
        icmpv6_header(transport_header['icmp_type'], transport_header['code'], transport_header['checksum'], transport_header['data'])
        
def ip(ip_header, transport_header):
    if ip_header['type'] == 'ipv4':
        ipv4_header(ip_header['version'], ip_header['header_length'], ip_header['ttl'], ip_header['ip_src'], ip_header['ip_dest'], ip_header['ip_proto'])
        transport(transport_header)
    elif ip_header['type'] == 'ipv6':
        ipv6_header(ip_header['version'], ip_header['traffic'], ip_header['flow'], ip_header['payload_length'], ip_header['next_header'], ip_header['hop'], ip_header['ip_src'], ip_header['ip_dest'])
        transport(transport_header)
    elif ip_header['type'] == 'arp':
        arp_message(ip_header['hw_type'], ip_header['p_type'], ip_header['hw_len'], ip_header['p_len'], ip_header['op'], ip_header['mac_src'], ip_header['ip_src'], ip_header['mac_dest'], ip_header['ip_dest'])

def frame(ethernet_header, ieee_header, ip_header, transport_header, src_filter, dest_filter, trans_filter):
    if ieee_header and ieee_header['type'] == 'LLC' and src_filter == 'any' and dest_filter == 'any' and trans_filter == 'any':
        ethernet_frame(ethernet_header['proto'], ethernet_header['dest'], ethernet_header['src'])
        llc_header(ieee_header['dsap'], ieee_header['ssap'], ieee_header['control'])
    
    if ieee_header and ieee_header['type'] == 'SNAP' and (src_filter == 'any' or src_filter == ip_header['ip_src']) and (dest_filter == 'any' or dest_filter == ip_header['ip_dest']) and (trans_filter == 'any' or trans_filter == transport_header['type']):
        ethernet_frame(ethernet_header['proto'], ethernet_header['dest'], ethernet_header['src'])
        llc_header(ieee_header['dsap'], ieee_header['ssap'], ieee_header['control'])
        snap_header(ieee_header['oui'], ieee_header['pid'])
        ip(ip_header, transport_header)
    
    if not ieee_header and (src_filter == 'any' or src_filter == ip_header['ip_src']) and (dest_filter == 'any' or dest_filter == ip_header['ip_dest']) and (trans_filter == 'any' or trans_filter == transport_header['type']):
        ethernet_frame(ethernet_header['proto'], ethernet_header['dest'], ethernet_header['src'])
        ip(ip_header, transport_header)
        
            

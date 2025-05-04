import sys

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

def wifi_header(header, output_file):
    out = output_file
    print("\n802.11, WIFI FRAME:", file=out)
    print(f"\tDuration: {header["duration"]} | Frame Control Header:", file=out)
    print(f"\t\tVersion: {header["version"]} | Frame Type: {header["ftype"]} | Subtype: {header["subtype"]}", file=out)
    print("\t\tFlags:", file=out)
    print(f"\t\t\tTo DS: {header["flags"]["to_ds"]} | From DS: {header["flags"]["from_ds"]} | More Frag: {header["flags"]["more_frag"]} | Retry: {header["flags"]["retry"]}", file=out)
    print(f"\t\t\tPower Management: {header["flags"]["power_mgmt"]} | More Data: {header["flags"]["more_data"]} | Protected Frame: {header["flags"]["protected_frame"]} | +HTC/Order: {header["flags"]["htc_order"]}", file=out)
    if header["flags"]["to_ds"] == 0 and header["flags"]["from_ds"] == 0:
        if header["ftype"] == 1:
            print(f"\t\t{control_frame[header["subtype"]]} | Receiver Address: {header["addr_1"]} | Transmitter Address: {header["addr_2"]}", file=out)
        else:
            if header["addr_1"] == "ff:ff:ff:ff:ff:ff":
                header["addr_1"] = "Broadcast"
            print(f"\t\tDestination: {header["addr_1"]} | Source: {header["addr_2"]} | BSSID: {header["addr_3"]}", file=out)
    elif header["flags"]["to_ds"] == 1 and header["flags"]["from_ds"] == 0:
        print(f"\t\tBSSID: {header["addr_1"]} | Source: {header["addr_2"]} | Destination: {header["addr_3"]}", file=out)
    elif header["flags"]["to_ds"] == 0 and header["flags"]["from_ds"] == 1:
        print(f"\t\tDestination: {header["addr_1"]} | BSSID: {header["addr_2"]} | Source: {header["addr_3"]}", file=out)
    else:
        print(f"\t\tReceiver Address: {header["addr_1"]} | Transmitter Address: {header["addr_2"]} | Destination: {header["addr_3"]} | Source: {header["addr_4"]}", file=out)

    

def ethernet_frame(eth_proto, mac_dest, mac_src, out): 
    print("\nEthernet Frame:", file=out)
    print(f"\tMAC Destination: {mac_dest} | MAC Source: {mac_src} | Protocol: {eth_proto}", file=out)

def snap_header(oui, pid, out):
    print('\tIEEE 802.3 LLC + SNAP HEADER:', file=out)
    print(f'OUI: {oui} | Protocol ID: {pid}', file=out)

def llc_header(dsap, ssap, control, out):
    print('\tIEEE 802.3 LLC Header:', file=out)
    print(f'DSAP: {dsap} | SSAP: {ssap} | Control: {control}', file=out)

def ipv6_header(version, traffic, flow, payload_length, next_header, hop, ip_src, ip_dest, out):
    print("\tIPv6 PACKET:", file=out)
    print(f"\t\tVersion: {version} | Traffic Class: {traffic} | Flow: {flow}", file=out)
    print(f"\t\tPayload Length: {payload_length} | Next Header: {next_header} | Hop Limit: {hop}", file=out)
    print(f"\t\tIP Source: {ip_src} | IP Destination: {ip_dest}", file=out)

def ipv4_header(version, header_length, ttl, ip_src, ip_dest, ip_proto, out):
    print("\tIPv4 PACKET:", file=out)
    print(f"\t\tVersion: {version} | Header Length: {header_length} | TTL: {ttl}", file=out)
    print(f"\t\tIP Source: {ip_src} | IP Destination: {ip_dest} | Protocol: {ip_proto}", file=out)

def arp_message(hw_type, p_type, hw_len, p_len, op, sender_mac, sender_ip, target_mac, target_ip, out):
    print("\tARP:", file=out)
    print(f"\t\tHardware Type: {hw_type} | Protocol Type: {p_type} | Hardware Length: {hw_len} | Protocol Length: {p_len}", file=out)
    if op == "1" or op == 1:
        print(f"\t\tRequest: who has IP:{target_ip} tell IP:{sender_ip}", file=out)
    elif op == "2" or op == 2:
        print(f"\t\tReply: IP:{sender_ip} is at Hardware: {sender_mac}", file=out)
    else:
        print("unknown arp type", file=out)

def icmpv6_header(icmp_type, code, checksum, data, out):
    print("\tICMPv6 Packet:", file=out)
    print(f"\t\tType: {icmp_type} | Code: {code} | Checksum: {checksum}", file=out)

def icmpv4_packet(icmp_type, code, checksum, data, out):
    print("\tICMPv4 Packet:", file=out)
    print(f"\t\tType: {icmp_type} | Code: {code} | Checksum: {checksum}", file=out)

def tcp_packet(src_port, dest_port, sequence_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data, out):
    print("\tTCP segment:", file=out)
    print(f"\t\tSource Port: {src_port} | Destination Port: {dest_port}", file=out)
    print(f"\t\tSequence: {sequence_num} | Acknowledgement: {ack}", file=out)
    print("\t\tFlags:", file=out)
    print(f"\t\t\tURG: {flag_urg} | ACK: {flag_ack} | PSH: {flag_psh} | RST: {flag_rst} | SYN: {flag_syn} | FIN: {flag_fin}", file=out)

def udp_packet(src_port, dest_port, length, data, out):
    print("\tUDP Segment:", file=out)
    print(f"\t\tSource Port: {src_port} | Destination Port: {dest_port} | Length: {length}", file=out)

def unknown_packet(data, out):
    print("\tUnknown Packet Data: ", file=out)
    print("\t\t", data.hex(), file=out)
    
def transport(transport_header, out):
    if transport_header['type'] == 'tcp':
        tcp_packet(transport_header['src_port'], transport_header['dest_port'], transport_header['sequence_num'], transport_header['ack'], transport_header['flag_urg'], transport_header['flag_ack'], transport_header['flag_psh'], transport_header['flag_rst'], transport_header['flag_syn'], transport_header['flag_fin'], transport_header['data'], out)
    elif transport_header['type'] == 'udp':
        udp_packet(transport_header['src_port'], transport_header['dest_port'], transport_header['size'], transport_header['data'], out)
    elif transport_header['type'] == 'icmp':
        icmpv4_packet(transport_header['icmp_type'], transport_header['code'], transport_header['checksum'], transport_header['data'], out)
    elif transport_header['type'] == 'icmpv6':
        icmpv6_header(transport_header['icmp_type'], transport_header['code'], transport_header['checksum'], transport_header['data'], out)
        
def ip(ip_header, transport_header, out):
    if ip_header['type'] == 'ipv4':
        ipv4_header(ip_header['version'], ip_header['header_length'], ip_header['ttl'], ip_header['ip_src'], ip_header['ip_dest'], ip_header['ip_proto'], out)
        transport(transport_header, out)
    elif ip_header['type'] == 'ipv6':
        ipv6_header(ip_header['version'], ip_header['traffic'], ip_header['flow'], ip_header['payload_length'], ip_header['next_header'], ip_header['hop'], ip_header['ip_src'], ip_header['ip_dest'], out)
        transport(transport_header, out)
    elif ip_header['type'] == 'arp':
        arp_message(ip_header['hw_type'], ip_header['p_type'], ip_header['hw_len'], ip_header['p_len'], ip_header['op'], ip_header['mac_src'], ip_header['ip_src'], ip_header['mac_dest'], ip_header['ip_dest'], out)

def frame(ethernet_header, ieee_header, ip_header, transport_header, output_file):
    out = output_file
    if ieee_header and ieee_header['type'] == 'LLC':
        ethernet_frame(ethernet_header['proto'], ethernet_header['dest'], ethernet_header['src'], output_file)
        llc_header(ieee_header['dsap'], ieee_header['ssap'], ieee_header['control'], output_file)
    
    if ieee_header and ieee_header['type'] == 'SNAP':
        ethernet_frame(ethernet_header['proto'], ethernet_header['dest'], ethernet_header['src'], output_file)
        llc_header(ieee_header['dsap'], ieee_header['ssap'], ieee_header['control'], output_file)
        snap_header(ieee_header['oui'], ieee_header['pid'], output_file)
        ip(ip_header, transport_header, output_file)
    
    if not ieee_header:
        ethernet_frame(ethernet_header['proto'], ethernet_header['dest'], ethernet_header['src'], output_file)
        ip(ip_header, transport_header, output_file)
        
            

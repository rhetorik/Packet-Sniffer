import textwrap

def format_multiline_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x[:02x]'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def wifi_header(header):
    print("\t802.11, WIFI FRAME:")
    print(f"\tDuration: {header["duration"]} Frame Control Header:")
    print(f"\t\tVersion: {header["version"]} Frame Type: {header["ftype"]} Subtype: {header["subtype"]}")
    print("\t\tFlags:")
    print(f"\t\t\tTo DS: {header["flags"]["to_ds"]} From DS: {header["flags"]["from_ds"]} More Frag: {header["flags"]["more_frag"]} Retry: {header["flags"]["retry"]}")
    print(f"\t\t\tPower Management: {header["flags"]["power_mgmt"]} More Data: {header["flags"]["more_data"]} Protected Frame: {header["flags"]["protected_frame"]} +HTC/Order: {header["flags"]["htc_order"]}")
    if header["flags"]["to_ds"] == 0 and header["flags"]["from_ds"] == 0:
        print(f"\t\tDestination: {header["addr_1"]} Source: {header["addr_2"]} BSSID: {header["addr_3"]}")
    elif header["flags"]["to_ds"] == 1 and header["flags"]["from_ds"] == 0:
        print(f"\t\tBSSID: {header["addr_1"]} Source: {header["addr_2"]} Destination: {header["addr_3"]}")
    elif header["flags"]["to_ds"] == 0 and header["flags"]["from_ds"] == 1:
        print(f"\t\tDestination: {header["addr_1"]} BSSID: {header["addr_2"]} Source: {header["addr_3"]}")
    else:
        print(f"\t\tReceiver Address: {header["addr_1"]} Transmitter Address: {header["addr_2"]} Destination: {header["addr_3"]} Source: {header["addr_4"]}")

    

def ethernet_frame(eth_proto, mac_dest, mac_src): 
    print("\nEthernet Frame:")
    print("\tDestination: ", mac_dest, " Source: ", mac_src, " Protocol: ", eth_proto)

def snap_header(oui, pid):
    print('\tIEEE 802.3 LLC + SNAP HEADER:')
    print('OUI: ', oui, ' Protocol ID: ', pid)

def llc_header(dsap, ssap, control):
    print('\tIEEE 802.3 LLC Header:')
    print('DSAP: ', dsap, ' SSAP: ', ssap, ' Control: ', control)

def ipv6_header(version, traffic, flow, payload_length, next_header, hop, ip_src, ip_dest):
    print("\tIPv6 PACKET:")
    print("\t\tVersion: ", version, " Traffic Class: ", traffic, " Flow: ", flow)
    print("\t\tPayload Length: ", payload_length, " Next Header: ", next_header, " Hop Limit: ", hop)
    print("\t\tSOURCE: ", ip_src, " DEST: ", ip_dest)

def ipv4_header(version, header_length, ttl, ip_src, ip_dest, ip_proto):
    print("\tIPv4 PACKET:")
    print("\t\tVersion: ", version, " Header Length: ", header_length, " TTL: ", ttl)
    print("\t\tSOURCE: ", ip_src, " DEST: ", ip_dest, " PROTOCOL: ", ip_proto)

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
    print("\t\tType: ", icmp_type, " Code: ", code, " Checksum: ", checksum)
    print("\t\tData:")
    print(format_multiline_data("\t\t\t", data))

def icmpv4_packet(icmp_type, code, checksum, data):
    print("\tICMPv4 Packet:")
    print("\t\tType: ", icmp_type, " Code: ", code, " Checksum: ", checksum)
    print("\t\tData:")
    print(format_multiline_data("\t\t\t", data))

def tcp_packet(src_port, dest_port, sequence_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data):
    print("\tTCP segment:")
    print("\t\tSource Port: ", src_port, " Destination Port: ", dest_port)
    print("\t\tSequence: ", sequence_num, " Acknowledgement: ", ack)
    print("\t\tFlags:")
    print("\t\t\tURG: ", flag_urg, " ACK: ", flag_ack, " PSH: ", flag_psh, " RST: ", flag_rst, " SYN: ", flag_syn, " FIN: ", flag_fin)
    print("\t\tData:")
    print(format_multiline_data("\t\t\t", data))

def udp_packet(src_port, dest_port, length, data):
    print("\tUDP Segment:")
    print("\t\tSource Port: ", src_port, " Destination Port: ", dest_port, " Length: ", length)
    print(format_multiline_data("\t\t", data))

def unknown_packet(data):
    print("\tData: ")
    print(format_multiline_data("\t\t", data))
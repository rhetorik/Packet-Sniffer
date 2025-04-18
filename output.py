import textwrap

def format_multiline_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x[:02x]'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

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
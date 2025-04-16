import sys
import socket
import struct
import textwrap
#bruh

def format_multiline_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x[:02x]'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def ipv6_convert(addr):
    hex_converted = []
    for i in range(0, len(addr), 2):
        hextet = (format(addr[i], '02x') + format(addr[i+1], '02x')).upper()
        hex_converted.append(hextet)
    return ":".join(hex_converted)


def eth_unpack(data):
    dest, src, proto, = struct.unpack('!6s6sH', data[:14])
    dest = ":".join(map('{:02x}'.format, dest)).upper() 
    src = ":".join(map('{:02x}'.format, src)).upper()
    proto = hex(proto)
    print(proto)
    return dest, src, proto, data[14:]

def IEEE_802_unpack(data):
    dsap, ssap, control = struct.unpack('! B B B', data[:3])
    if hex(dsap) == '0xAA' and hex(ssap) == '0xAA' and control == 0x03:
        #SNAP header
        type = 'SNAP'
        oui = data[3:6]
        pid = struct.unpack('!H', data[6:8])[0]
        return {'type':type, 'oui':oui.hex(), 'pid':hex(pid), 'payload':data[8:]}
    else:
        #only LLC 
        type = 'LLC'
        return {'type':type, 'dsap':hex(dsap), 'ssap':hex(ssap), 'control':control, 'payload':data[3:]}

def ipv4_unpack(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, ip_proto, ip_src, ip_dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    ip_src = ".".join(map(str, ip_src))
    ip_dest = ".".join(map(str, ip_dest))
    return version, ttl, ip_proto, ip_src, ip_dest, header_length, data[header_length:]

def ipv6_unpack(data):
    version_traffic_flow, payload_length, next_header, hop, ip_src, ip_dest = struct.unpack('! I H B B 16s 16s', data[:40])
    version = version_traffic_flow >> 28
    traffic = (version_traffic_flow >> 20) & 0xff
    flow = version_traffic_flow & 0xfffff
    ip_src = ipv6_convert(ip_src)
    ip_dest = ipv6_convert(ip_dest)
    return version, traffic, flow, payload_length, next_header, hop, ip_src, ip_dest, data[40:]


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def icmpv6_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def tcp_segment(data):
    (src_port, dest_port, sequence_num, ack, flags) = struct.unpack('! H H L L H', data[:14])
    offset = (flags >> 12) * 4
    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = flags & 1
    return src_port, dest_port, sequence_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    
    

def main():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        data, addr = sock.recvfrom(65565)
        mac_dest, mac_src, eth_proto, payload = eth_unpack(data)
        eth_proto = int(eth_proto, 16)
        print("\nEthernet Frame:")
        print("\tDestination: ", mac_dest, " Source: ", mac_src, " Protocol: ", eth_proto)
        
        if eth_proto < 0x600:
            ieee_header = IEEE_802_unpack(payload)
            if ieee_header['type'] == "SNAP":
                print('\tIEEE 802.3 LLC + SNAP HEADER:')
                print('OUI: ', ieee_header['oui'], ' Protocol ID: ', ieee_header['pid'])
                eth_proto = ieee_header['pid']
                eth_proto = int(eth_proto, 16)
                

            elif ieee_header['type'] == "LLC":
                print('\tIEEE 802.3 LLC Header:')
                print('DSAP: ', ieee_header['dsap'], ' SSAP: ', ieee_header['ssap'], ' Control: ', ieee_header['control'])


        if eth_proto == 0x800:
            version, ttl, ip_proto, ip_src, ip_dest, header_length, ip_payload = ipv4_unpack(payload)
            print("\tIPv4 PACKET:")
            print("\t\tVersion: ", version, " Header Length: ", header_length, " TTL: ", ttl)
            print("\t\tSOURCE: ", ip_src, " DEST: ", ip_dest, " PROTOCOL: ", ip_proto)

            if ip_proto == 1:
                icmp_type, code, checksum, data = icmp_packet(ip_payload)
                print("\tICMP Packet:")
                print("\t\tType: ", icmp_type, " Code: ", code, " Checksum: ", checksum)
                print("\t\tData:")
                print(format_multiline_data("\t\t\t", data))
            elif ip_proto == 6:
                (src_port, dest_port, sequence_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(ip_payload)
                print("\tTCP segment:")
                print("\t\tSource Port: ", src_port, " Destination Port: ", dest_port)
                print("\t\tSequence: ", sequence_num, " Acknowledgement: ", ack)
                print("\t\tFlags:")
                print("\t\t\tURG: ", flag_urg, " ACK: ", flag_ack, " PSH: ", flag_psh, " RST: ", flag_rst, " SYN: ", flag_syn, " FIN: ", flag_fin)
                print("\t\tData:")
                print(format_multiline_data("\t\t\t", data))
            elif ip_proto == 17:
                src_port, dest_port, length, data = udp_segment(ip_payload)
                print("\tUDP Segment:")
                print("\t\tSource Port: ", src_port, " Destination Port: ", dest_port, " Length: ", length)
                print(format_multiline_data("\t\t", data))
            else:
                print("\tData: ")
                print(format_multiline_data("\t\t", ip_payload))

        #IPv6
        elif eth_proto == 0x86dd:
            version, traffic, flow, payload_length, next_header, hop, ip_src, ip_dest, ip_payload = ipv6_unpack(payload)
            print("\tIPv6 PACKET:")
            print("\t\tVersion: ", version, " Traffic Class: ", traffic, " Flow: ", flow)
            print("\t\tPayload Length: ", payload_length, " Next Header: ", next_header, " Hop Limit: ", hop)
            print("\t\tSOURCE: ", ip_src, " DEST: ", ip_dest)

            if next_header == 1:
                icmp_type, code, checksum, data = icmp_packet(ip_payload)
                print("\tICMP Packet:")
                print("\t\tType: ", icmp_type, " Code: ", code, " Checksum: ", checksum)
                print("\t\tData:")
                print(format_multiline_data("\t\t\t", data))
            elif next_header == 6:
                (src_port, dest_port, sequence_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(ip_payload)
                print("\tTCP segment:")
                print("\t\tSource Port: ", src_port, " Destination Port: ", dest_port)
                print("\t\tSequence: ", sequence_num, " Acknowledgement: ", ack)
                print("\t\tFlags:")
                print("\t\t\tURG: ", flag_urg, " ACK: ", flag_ack, " PSH: ", flag_psh, " RST: ", flag_rst, " SYN: ", flag_syn, " FIN: ", flag_fin)
                print("\t\tData:")
                print(format_multiline_data("\t\t\t", data))
            elif next_header == 17:
                src_port, dest_port, length, data = udp_segment(ip_payload)
                print("\tUDP Segment:")
                print("\t\tSource Port: ", src_port, " Destination Port: ", dest_port, " Length: ", length)
                print(format_multiline_data("\t\t", data))
            elif next_header == 58:
                icmp_type, code, checksum, data = icmpv6_packet(ip_payload)
                print("\tICMPv6 Packet:")
                print("\t\tType: ", icmp_type, " Code: ", code, " Checksum: ", checksum)
                print("\t\tData:")
                print(format_multiline_data("\t\t\t", data))
            else:
                print("\tData: ")
                print(format_multiline_data("\t\t", ip_payload))    



         
main()


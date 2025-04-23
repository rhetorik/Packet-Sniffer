import socket
import struct
import select
import output



def ipv6_convert(addr):
    hex_converted = []
    for i in range(0, len(addr), 2):
        hextet = (format(addr[i], '02x') + format(addr[i+1], '02x')).upper()
        hex_converted.append(hextet)
    return ":".join(hex_converted)

def frame_control_flags(flags):
    return {"to_ds": ((flags >> 0) & 1),
            "from_ds": ((flags >> 1) & 1),
            "more_frag": ((flags >> 2) & 1),
            "retry": ((flags >> 3) & 1),
            "power_mgmt": ((flags >> 4) & 1),
            "more_data": ((flags >> 5) & 1),
            "protected_frame": ((flags >> 6) & 1),
            "htc_order": ((flags >> 7) & 1)}



def wifi_unpack(data):
    radiotap_version = data[0]
    if radiotap_version != 0:
        print("NO RADIOTAP HEADER THIS MIGHT BE ETHERNET")
        return
    radiotap_length = struct.unpack("<2x H", data[:4])[0]
    data = data[radiotap_length:]

    frame_control, duration = struct.unpack("<HH", data[:4])
    version = frame_control & 0b11
    ftype = (frame_control >> 2) & 0b11
    subtype = (frame_control >> 4) & 0b1111
    flags = frame_control_flags(frame_control >> 8)
    addr_1 = ":".join(map('{:02x}'.format, data[4:10])).upper(),
    addr_2 = ":".join(map('{:02x}'.format, data[10:16])).upper(),
    addr_3 = ":".join(map('{:02x}'.format, data[16:22])).upper(),
    addr_4 = None
    qos = None

    header_length = 24
    start = 24
    #ADDR 4 present
    if flags['to_ds'] and flags['from_ds']:
        header_length += 6
        addr_4 = ":".join(map('{:02x}'.format, data[start:start+6])).upper()
        start += 6
    #QoS Control Field present
    if ftype == 2 and subtype == 0b1000:
        header_length += 2
        qos = struct.unpack("<H", data[start:start+2])[0]
        start += 2
    #HTC Control present
    if flags["htc_order"]:
        header_length += 4
        start += 4
    if ftype != 2:
        return {"frame_control":frame_control,
            "duration": duration,
            "version": version,
            "ftype": ftype,
            "subtype": subtype,
            "flags": flags,
            "addr_1": addr_1,
            "addr_2": addr_2,
            "addr_3": addr_3,
            "addr_4": addr_4,
            "qos": qos,
            "payload":data[start:]}
    
    llc = IEEE_802_unpack(data[header_length:])
    if llc['type'] == "LLC":
        output.llc_header(llc['dsap'], llc['ssap'], llc['control'])
        return {"frame_control":frame_control,
            "duration": duration,
            "version": version,
            "ftype": ftype,
            "subtype": subtype,
            "flags": flags,
            "addr_1": addr_1,
            "addr_2": addr_2,
            "addr_3": addr_3,
            "addr_4": addr_4,
            "qos": qos,
            "payload":llc['payload']}
    elif llc['type'] == "SNAP":
        eth_proto = llc['pid']
        eth_proto = int(eth_proto, 16)
        print("WIFI ETHERTYPE: ", eth_proto)
        identify_ethertype(eth_proto, llc['payload'])
        return {"frame_control":frame_control,
            "duration": duration,
            "version": version,
            "ftype": ftype,
            "subtype": subtype,
            "flags": flags,
            "addr_1": addr_1,
            "addr_2": addr_2,
            "addr_3": addr_3,
            "addr_4": addr_4,
            "qos": qos,
            "payload":llc['payload']}
    





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
        return {'type':type, 'dsap':hex(dsap), 'ssap':hex(ssap), 'control':control, 'oui':oui.hex(), 'pid':hex(pid), 'payload':data[8:]}
    else:
        #only LLC 
        type = 'LLC'
        return {'type':type, 'dsap':hex(dsap), 'ssap':hex(ssap), 'control':control, 'payload':data[3:]}

def arp_unpack(data):
    hw_type, p_type, hw_len, p_len, op, sender_mac, sender_ip, target_mac, target_ip = struct.unpack("!H H B B H 6s 4s 6s 4s", data[:28])
    sender_mac = ":".join(map('{:02x}'.format, sender_mac)).upper() 
    target_mac = ":".join(map('{:02x}'.format, target_mac)).upper()
    sender_ip = ".".join(map(str, sender_ip))
    target_ip = ".".join(map(str, target_ip)) 
    return hw_type, p_type, hw_len, p_len, op, sender_mac, sender_ip, target_mac, target_ip

def ipv4_unpack(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    total_length = int.from_bytes(data[2:4], byteorder="big")
    ttl, ip_proto, ip_src, ip_dest = struct.unpack('! 8x B B 2x 4s 4s', data[:header_length])
    ip_src = ".".join(map(str, ip_src))
    ip_dest = ".".join(map(str, ip_dest))
    return version, ttl, ip_proto, ip_src, ip_dest, header_length, data[header_length:]

def ipv6_unpack(data):
    version_traffic_flow, payload_length, next_header, hop, ip_src, ip_dest = struct.unpack('! I H B B 16s 16s', data[:40])
    payload_length = int.from_bytes(data[4:6], byteorder="big")
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
    (src_port, dest_port, sequence_num, ack, flags) = struct.unpack('! H H I I H', data[:14])
    print("HEADER: ", data[:20].hex())
    offset = (flags >> 12) * 4
    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = flags & 1
    return src_port, dest_port, sequence_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    
def identify_transport_layer(ip_proto, ip_payload):
    if ip_proto == 1:
        icmp_type, code, checksum, data = icmp_packet(ip_payload)
        output.icmpv4_packet(icmp_type, code, checksum, data)
    elif ip_proto == 6:
        (src_port, dest_port, sequence_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(ip_payload)
        output.tcp_packet(src_port, dest_port, sequence_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data)              
    elif ip_proto == 17:
        src_port, dest_port, length, data = udp_segment(ip_payload)
        output.udp_packet(src_port, dest_port, length, data)
    elif ip_proto == 58:
        icmp_type, code, checksum, data = icmpv6_packet(ip_payload)
        output.icmpv6_header(icmp_type, code, checksum, data)
    else:
        output.unkown_data(ip_payload)

def identify_ethertype(eth_proto, data):
    #IPv4
    if eth_proto == 0x800:
        version, ttl, ip_proto, ip_src, ip_dest, header_length, ip_payload = ipv4_unpack(data)
        output.ipv4_header(version, header_length, ttl, ip_src, ip_dest, ip_proto)
        identify_transport_layer(ip_proto, ip_payload)
                    

    #IPv6
    elif eth_proto == 0x86dd:
        version, traffic, flow, payload_length, next_header, hop, ip_src, ip_dest, ip_payload = ipv6_unpack(data)
        output.ipv6_header(version, traffic, flow, payload_length, next_header, hop, ip_src, ip_dest)
        identify_transport_layer(next_header, ip_payload)

    #ARP
    elif eth_proto == 0x806:
        hw_type, p_type, hw_len, p_len, op, sender_mac, sender_ip, target_mac, target_ip = arp_unpack(data)
        output.arp_message(hw_type, p_type, hw_len, p_len, op, sender_mac, sender_ip, target_mac, target_ip)

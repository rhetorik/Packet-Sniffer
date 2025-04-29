import socket
import struct
import array
import argparse

arg_flags = argparse.ArgumentParser()

arg_flags.add_argument('--tcp', action='store_true')
arg_flags.add_argument('--udp', action='store_true')
arg_flags.add_argument('--src', type=str)
arg_flags.add_argument('--destip', type=str)
arg_flags.add_argument('--destmac', type=str)

interface = 'enp0s3'


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    res = sum(array.array("H", data))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    return ~res & 0xffff

def tcp(src_mac, dest_mac, src_ip, dest_ip, src_port, dest_port):
    #IP header
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_total_length = 40
    ip_id = 12345
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_src_addr = socket.inet_aton(src_ip)
    ip_dest_addr = socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header  = struct.pack('! B B H H H B B H 4s 4s', ip_ihl_ver, ip_tos, ip_total_length, ip_id, ip_frag_off, ip_ttl,
                            ip_proto, ip_check, ip_src_addr, ip_dest_addr)
    ip_check = checksum(ip_header)
    ip_header  = struct.pack('! B B H H H B B H 4s 4s', ip_ihl_ver, ip_tos, ip_total_length, ip_id, ip_frag_off, ip_ttl,
                            ip_proto, ip_check, ip_src_addr, ip_dest_addr)

    #TCP header
    tcp_offset_res = (5 << 4) + 0
    tcp_flags = 0x02
    tcp_win = 65535
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_seq_num = 123456
    tcp_header = struct.pack('! H H L L B B H H H', src_port, dest_port, tcp_seq_num, 0, tcp_offset_res, tcp_flags, tcp_win,
                            tcp_check, tcp_urg_ptr)
    pseudo_header = struct.pack('! 4s 4s B B H', ip_src_addr, ip_dest_addr, 0, socket.IPPROTO_TCP, len(tcp_header))
    tcp_check = checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack('! H H L L B B H H H', src_port, dest_port, tcp_seq_num, 0, tcp_offset_res, tcp_flags, tcp_win,
                            tcp_check, tcp_urg_ptr)

    #Ethernet header
    eth_proto = 0x800
    eth_header = struct.pack('! 6s 6s H', dest_mac, src_mac, eth_proto)

    packet = eth_header + ip_header + tcp_header
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
        sock.send(packet)
        print(f"sent spoofed packet from {src_ip}:{src_port} to {dest_ip}:{dest_port}")
        return
    except socket.error:
        print("ERROR SENDING TCP MESSAGE")
        return
        


def udp(src_mac, dest_mac, src_ip, dest_ip, src_port, dest_port):
    #IP header
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_total_length = 40
    ip_id = 12345
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0
    ip_src_addr = socket.inet_aton(src_ip)
    ip_dest_addr = socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header  = struct.pack('! B B H H H B B H 4s 4s', ip_ihl_ver, ip_tos, ip_total_length, ip_id, ip_frag_off, ip_ttl,
                            ip_proto, ip_check, ip_src_addr, ip_dest_addr)
    ip_check = checksum(ip_header)
    ip_header  = struct.pack('! B B H H H B B H 4s 4s', ip_ihl_ver, ip_tos, ip_total_length, ip_id, ip_frag_off, ip_ttl,
                            ip_proto, ip_check, ip_src_addr, ip_dest_addr)
    
    
    #UDP header
    udp_length = 8
    udp_check = 0
    udp_header = struct.pack('! H H H H', src_port, dest_port, udp_length, udp_check)
    udp_check = checksum(udp_header)
    udp_header = struct.pack('! H H H H', src_port, dest_port, udp_length, udp_check)

    #Ethernet header
    eth_proto = 0x800
    eth_header = struct.pack('! 6s 6s H', dest_mac, src_mac, eth_proto)

    packet = eth_header + ip_header + udp_header

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
        sock.send(packet)
        print(f"sent spoofed udp packet from {src_ip}:{src_port} to {dest_ip}:{dest_port}")
        return
    except socket.error:
        print("ERROR SENDING UDP MESSAGE")
        return

def main():
    src_mac = b'\x00\x11\x22\x33\x44\x55'
    dest_mac = b'\x3C\x7C\x3F\xEE\xC6\xED'
    src_ip = '192.168.1.1'
    dest_ip = '192.168.1.195'
    src_port = 8080
    dest_port = 8080
    

    args = arg_flags.parse_args()

    if args.src:
        try:
            test = socket.inet_aton(args.src)
            src_ip = args.src
        except socket.error:
            print("INVAILD SOURCE IP FORMAT")
            return
    if args.destip:
        try:
            test = socket.inet_aton(args.destip)
            dest_ip = args.destip
        except socket.error:
            print("INVALID DESTINATION IP FORMAT")
            return
    if args.destmac:
        test = args.destmac.replace(":", " ")
        dest_mac = bytes.fromhex(test)
    if args.tcp:
        tcp(src_mac, dest_mac, src_ip, dest_ip, src_port, dest_port)
        return
    if args.udp:
        udp(src_mac, dest_mac, src_ip, dest_ip, src_port, dest_port)
        return

main()


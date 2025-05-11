# sniffer.py
import socket
import struct

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def main():
    # Create a raw socket
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("[*] Sniffing started... Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

            if eth_proto == 8:  # IPv4
                version_length, ttl, proto, src, target, data = ipv4_packet(data)
                print('IPv4 Packet:')
                print(f'From: {src} to {target}')
                print(f'TTL: {ttl}, Protocol: {proto}')

    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped.")

if _name_ == '_main_':
    main()

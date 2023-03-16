import socket
import struct
import textwrap
import datetime
import time


# Capturing raw packets

# Unpacking Layer 2 (Data Link) frames by taking out first 14 bytes
# Returns dst mac, src mac, protocol, and the data after 14 bytes [payload]
def L2_frame(data):
   dst_mac, src_mac, L2_proto = struct.unpack('! 6s 6s H', data[:14])
   return get_mac(dst_mac), get_mac(src_mac), socket.htons(L2_proto), data[14:]


# Fuction to return hexadecimal MAC address format
def get_mac(bytes_mac):
   bytes_str = map('{:02x}'.format, bytes_mac)
   return ':'.join(bytes_str).upper()


# Unpacking Layer 3 (Network) Packets by taking out first 20 bytes
# Returns time to live, network protocol, src IP, dst IP, and data after IP header length bytes [payload]
def L3_packet(data):
   IPver_head_length = data[0]
   IPhead_length = (IPver_head_length & 15) * 4 # Bitwise and operator to get the header length. Header length used to know where payload starts
   time_to_live, L3_proto, src_IP, dst_IP = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) # IP header is 20 bytes long
   return time_to_live, L3_proto, get_IP(src_IP), get_IP(dst_IP), data[IPhead_length:]


# Function to return IP address format
def get_IP(bytes_IP):
   return '.'.join(map(str, bytes_IP))


# Unpacking Layer 3 ICMP packets by taking out first 4 bytes
# Returns ICMP type, checksum, and data after 4 bytes [payload]
def icmp_unpack(data):
   icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
   return icmp_type, checksum, data[4:]


# Unpacking Layer 4 TCP segments by taking out first 14 bytes
# Returns source port, destination port, sequence, acknowledgement, and data after offset [payload]
def tcp_unpack(data):
   (src_port, dst_port, seq, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
   offset = (offset_reserved_flags >> 12) * 4
   return src_port, dst_port, seq, ack, data[offset:]


# Unpacking Layer 4 UDP segments by taking out first 8 bytes
def udp_unpack(data):
   src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
   return src_port, dst_port, size, data[8:]


# Function to format multi-line data
def line_format(prefix, string, size=80):
   size -= len(prefix)
   if isinstance(string, bytes):
      string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
      if size % 2:
         size -= 1
   return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def dns_host_lookup(addr):
    try:
        return socket.gethostbyaddr(addr)
    except socket.herror:
        return None, None, None

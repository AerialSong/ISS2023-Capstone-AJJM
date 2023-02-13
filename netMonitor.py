import socket
import struct
import textwrap
import datetime


# Capturing raw packets
def monitor():
   conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
   datetime_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   packet_num = 0
   format_star1 = "    *"
   format_star2 = "\t*"
   format_tab = "\t   "

   # A loop to contantly receive a packet
   while True:
      inet_data, addr = conn.recvfrom(65536) # buffersize
      dst_mac, src_mac, L2_proto, data = L2_frame(inet_data)
      print("-" * 200, f"\nNumber {packet_num} | Date and time: {datetime_now}")
      print(format_star1, f"Ethernet Frame {packet_num} - Dst MAC: {dst_mac}, Src MAC: {src_mac}, Ethernet Protocol ID: {L2_proto}")
      packet_num += 1
   
      # Ethernet frame ID 8 is IPv4
      if L2_proto == 8:
         (time_to_live, L3_proto, src_IP, dst_IP, data) = L3_packet(data)
         print(format_star1, f"IPv4 Packet - Src IP: {src_IP}, Dst IP: {dst_IP}, IP Protocol ID: {L3_proto}, TTL: {time_to_live}")

         # IP Protocol ID 1 is ICMP
         if L3_proto == 1:
            icmp_type, checksum, data = icmp_unpack(data)
            print(format_star1, f"ICMP Packet - Type: {icmp_type}, Checksum: {checksum}")
            print(format_star2, "Data:\n", line_format(format_tab, data))
         
         # IP Protocol ID 6 is TCP
         elif L3_proto == 6:
            (src_port, dst_port, seq, ack, data) = tcp_unpack(data)
            print(format_star1, f"TCP Segment - Src Port: {src_port}, Dst Port: {dst_port}, Seq: {seq}, Ack: {ack}")
            print(format_star2, "Data:\n", line_format(format_tab, data))
         
         # IP Protocol ID 17 is UDP
         elif L3_proto == 17:
            src_port, dst_port, size, data = udp_unpack(data)
            print(format_star1, f"UDP Segment - Src Port: {src_port}, Dst Port: {dst_port}, Size: {size}")
            print(format_star2, "Data:\n", line_format(format_tab, data))

         # Other IP Protocols
         else:
            print(format_star1, "IP Protocol that is not ICMP, TCP, and UDP - Data:")
            print(line_format(format_tab, data))
      
      else:
         print("Data other than IPv4:")
         print(line_format(format_tab, data))
      

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
# Returnin ICMP type, checksum, and data after 4 bytes [payload]
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


# Executing the Program
try: 
   monitor()

except KeyboardInterrupt:
   pass

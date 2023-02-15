import argparse
import json
import os
from os.path import exists
import sys
import time as clock
import socket
import struct
import textwrap
import datetime
import subprocess

# Code by Arthur Kutepov, Jomel Jay 2023

# The plan:
# monitor() gets network packet info
# that info is put into variables
# Print the variables out like you did in your output code
# Argparse is now used to filter for particular network data
# If any packets are coming from 1.1.1.1
# and you want to check for only those packets
# you type: python3 scoriaoutputnetmonitor.py -dest 1.1.1.1
# and it will show you only the packets coming from that address

def monitor(args):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    datetime_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    packet_num = 0
    format_star1 = "    *"
    format_star2 = "\t*"
    format_tab = "\t   "
    path = "arg.txt"
    arglist = []
    arglist.append(args.destination, args.source, args.srcport, args.destport, args.srcmac, args.destmac, args.date, args.time)

    
    # local list variable to store json namespace data
    mydict = {}
    # Checks if newly created txt file exists
    # if so, the arguments are then changed in real time
    while True:
        if exists(path):
            with open(path, "r") as f:
                mydict = json.load(f)
                f.close()
            os.remove(path)
                   
            if mydict["destination"] != None:
                args.destination = mydict["destination"]
            if mydict["source"] != None:
                args.source = mydict["source"]
            if mydict["protocol"] != None:
                args.protocol = mydict["protocol"]
            if mydict["srcport"] != None:
                args.srcport = mydict["srcport"]
            if mydict["destport"] != None:
                args.destport = mydict["destport"]
            if mydict["srcmac"] != None:
                args.srcmac = mydict["srcmac"]
            if mydict["destmac"] != None:
                args.destmac = mydict["destmac"]
            if mydict["date"] != None:
                args.date = mydict["date"]
            if mydict["time"] != None:
                args.time = mydict["time"]
        else:
            pass
            
        '''except KeyboardInterrupt:
            print("\nExiting Program...\n")
            sys.tracebacklimit = 0'''


    # the plan: upon entering an argument, say if someone searches for -dest 3.3.3.3, then it will check if 
    # the destination ip matches that
    # and if it does, it will print the packet
    # This will involve a lot of trial and error

    # put all packet information into a list
    # put all argument values in a list
    # if all the entered argument values are in the packet list
    # print that packet
    # if not all entered arg values are in the packet list
    # DO NOT print packet

    # Checks if ANY of the argument values or NOT NONE
    # If ANY of them are NOT NONE, then it can do the filter functionality


    # A loop to contantly receive a packet
        inet_data, addr = conn.recvfrom(65536) # buffersize
        dst_mac, src_mac, L2_proto, data = L2_frame(inet_data)
        print(f"| Num: {packet_num} | Src MAC: {src_mac} | Dest MAC: {dst_mac} ", end='')
        #print("-" * 200, f"\nNumber {packet_num} | Date and time: {datetime_now}")
        #print(format_star1, f"Ethernet Frame {packet_num} - Dst MAC: {dst_mac}, Src MAC: {src_mac}, Ethernet Protocol ID: {L2_proto}")
        packet_num += 1
   
        # Ethernet frame ID 8 is IPv4
        if L2_proto == 8 and args.destination == None and args.source == None:
            (time_to_live, L3_proto, src_IP, dst_IP, data) = L3_packet(data)
            print(f"L3_proto: {L3_proto}")
            print(f"| Dest IP: {dst_IP} | Source IP: {src_IP} ", end='')
            #print(format_star1, f"IPv4 Packet - Src IP: {src_IP}, Dst IP: {dst_IP}, IP Protocol ID: {L3_proto}, TTL: {time_to_live}")

        elif L2_proto == 8 and args.destination != None:
            (time_to_live, L3_proto, src_IP, dst_IP, data) = L3_packet(data)
            if dst_IP == args.destination[0]:
                print(f"| Dest IP: {dst_IP} ", end='')
        
        elif L2_proto == 8 and args.source != None:
            (L3_proto, src_IP, data) = L3_packet(data)
            if src_IP == args.source[0]:
                print(f"| Source IP: {src_IP} ", end='')

        # IP Protocol ID 1 is ICMP
        if L3_proto == 1:
            icmp_type, checksum, data = icmp_unpack(data)
            #print(format_star1, f"ICMP Packet - Type: {icmp_type}, Checksum: {checksum}")
            #print(format_star2, "Data:\n", line_format(format_tab, data))
         
        # IP Protocol ID 6 is TCP
        elif L3_proto == 6:
            (src_port, dst_port, seq, ack, data) = tcp_unpack(data)
            print(f"| Protocol: TCP | Src Port: {src_port} | Dest Port: {dst_port} |\n", end='')
            #print(format_star1, f"TCP Segment - Src Port: {src_port}, Dst Port: {dst_port}, Seq: {seq}, Ack: {ack}")
            #print(format_star2, "Data:\n", line_format(format_tab, data))
         
        # IP Protocol ID 17 is UDP
        elif L3_proto == 17:
            src_port, dst_port, size, data = udp_unpack(data)
            print(f"| Protocol: UDP | Src Port: {src_port} | Dest Port: {dst_port} |\n")
            #print(format_star1, f"UDP Segment - Src Port: {src_port}, Dst Port: {dst_port}, Size: {size}")
            #print(format_star2, "Data:\n", line_format(format_tab, data))

        # Other IP Protocols
        '''
        else:
        print(format_star1, "Data:")
            print(line_format(format_tab, data))'''
      
        '''
        else:
            print("Data:")
            print(line_format(format_tab, data))'''
        clock.sleep
      


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


# Print function. All arguments are sent here and printed
'''def printargs(args):
    path = "arg.txt"
    
    # local list variable to store json namespace data
    mydict = {}
    try:
        while True:
            # Checks if newly created txt file exists
            # if so, the arguments are then changed in real time
            if exists(path):
                with open(path, "r") as f:
                    mydict = json.load(f)
                    f.close()
                os.remove(path)
                   

                if mydict["destination"] != None:
                    args.destination = mydict["destination"]
                if mydict["source"] != None:
                    args.source = mydict["source"]
                if mydict["protocol"] != None:
                    args.protocol = mydict["protocol"]
                if mydict["srcport"] != None:
                    args.srcport = mydict["srcport"]
                if mydict["destport"] != None:
                    args.destport = mydict["destport"]
                if mydict["srcmac"] != None:
                    args.srcmac = mydict["srcmac"]
                if mydict["destmac"] != None:
                    args.destmac = mydict["destmac"]
                if mydict["date"] != None:
                    args.date = mydict["date"]
                if mydict["time"] != None:
                    args.time = mydict["time"]
        
                
        # Checks if each argument in the namespace is null or not
        # If not, they print

        # Additional if statements are here to check if the entered string of an argument is none
        # If so, it will define the entered argument as None
            if args.destination != None and args.destination[0] != 'none':
                print("|", end='')
                print(f" Dest IP: {args.destination[0]} ", end='')
            elif args.destination != None and args.destination[0] == 'none':
                args.destination = None

            if args.source != None and args.source[0] != 'none':
                print("|", end='')
                print(f" Source IP: {args.source[0]} ", end='')
            elif args.source != None and args.source[0] == 'none':
                args.source = None

            if args.protocol != None and args.protocol[0] != 'none':
                print("|", end='')
                print(f" Protocol: {args.protocol[0]} ", end='')
            elif args.protocol != None and args.protocol[0] == 'none':
                args.protocol = None

            if args.srcport != None and args.srcport[0] != 'none':
                print("|", end='')
                print(f" Source Port: {args.srcport[0]} ", end='')
            elif args.srcport != None and args.srcport[0] == 'none':
                args.srcport = None

            if args.destport != None and args.destport[0] != 'none':
                print("|", end='')
                print(f" Destination Port: {args.destport[0]} ", end='')
            elif args.destport != None and args.destport[0] == 'none':
                args.destport = None

            if args.srcmac != None and args.srcmac[0] != 'none':
                print("|", end='')
                print(f" Source MAC: {args.srcmac[0]} ", end='')
            elif args.srcmac != None and args.srcmac[0] == 'none':
                args.srcmac = None
            
            if args.destmac != None and args.destmac[0] != 'none':
                print("|", end='')
                print(f" Destination MAC: {args.destmac[0]} ", end='')
            elif args.destmac != None and args.destmac[0] == 'none':
                args.destmac = None

            if args.date != None and args.date[0] != 'none':
                print("|", end='')
                print(f" Date: {args.date[0]} ", end='')
            elif args.date != None and args.date[0] == 'none':
                args.date = None

            if args.time != None and args.time[0] != 'none':
                print("|", end='')
                print(f" Time: {args.time[0]} ", end='')
            elif args.time != None and args.time[0] == 'none':
                args.time = None

            print("|", end='')
            clock.sleep(1)
            print("\n")
        
    except KeyboardInterrupt:
        print("\nExiting Program...\n")
        sys.tracebacklimit = 0'''

if __name__ == '__main__':
    # parser object
    parser = argparse.ArgumentParser(description="A lightweight command-line based Network Traffic Analyzer")

    parser.add_argument("-dest", "--destination", type=str, nargs=1, metavar="destination_ip", default=None, help="Destination IP Address")
    parser.add_argument("-s", "--source", type=str, nargs=1, metavar="source_ip", default=None, help="Source IP Address")
    parser.add_argument("-pr", "--protocol", type=str, nargs=1, metavar="protocol_name", default=None, help="Type of protocol")
    parser.add_argument("-sp", "--srcport", type=str, nargs=1, metavar="src_port_num", default=None, help="Source Port Number")
    parser.add_argument("-dp", "--destport", type=str, nargs=1, metavar="dest_port_num", default=None, help="Destination Port Number")
    parser.add_argument("-sm" , "--srcmac", type=str, nargs=1, metavar="src_mac", default=None, help="Source MAC address")
    parser.add_argument("-dm" , "--destmac", type=str, nargs=1, metavar="dest_mac", default=None, help="Destination MAC address")
    parser.add_argument("-d", "--date", type=str, nargs=1, metavar="date", default=None, help="Date packet was made; Syntax = MMdd")
    parser.add_argument("-t", "--time", type=str, nargs=1, metavar="time", default=None, help="Time packet was made; Syntax = HHmm")

    args = parser.parse_args()

    # Executing the Program
    try: 
        monitor(args)

    except KeyboardInterrupt:
        pass

    #printargs(args)
    # To do:
    # Import netMonitor as a module and see if you can capture any network info
    # You have your output code, this one, and you have a second script which takes a variable from this one and changes it and sends it back to this one
    # both scripts are running at the same time.

    # Think about a hypothetical client that this product is made for. Decide what they will want and how you are going to implement it.

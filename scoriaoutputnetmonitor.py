import argparse
import json
import os
from os.path import exists
import time as clock
import socket
import struct
import textwrap
import datetime
import subprocess
import re
import sys
import ipaddress

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
    datetime_month = int(datetime.datetime.now().strftime("%m"))#.strftime("%Y-%m-%d %H:%M:%S")
    datetime_day = datetime.datetime.now().strftime("%d")
    datetime_hour = datetime.datetime.now().strftime("%H")
    datetime_min = datetime.datetime.now().strftime("%M")
    packet_num = 0
    path = "arg.txt"
    
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


        # If entered argument in input script is "none" then the argument becomes null
        if args.destination != None and args.destination[0] == 'none':
            args.destination = None

        if args.source != None and args.source[0] == 'none':
            args.source = None

        if args.protocol != None and args.protocol[0] == 'none':
            args.protocol = None

        if args.srcport != None and args.srcport[0] == 'none':
            args.srcport = None

        if args.destport != None and args.destport[0] == 'none':
            args.destport = None

        if args.srcmac != None and args.srcmac[0] == 'none':
            args.srcmac = None
            
        if args.destmac != None and args.destmac[0] == 'none':
            args.destmac = None

        if args.date != None and args.date[0] == 'none':
            args.date = None

        if args.time != None and args.time[0] == 'none':
            args.time = None

        arglist = []

        if args.destination != None:
            arglist.append(args.destination[0])
        if args.source != None:
            arglist.append(args.source[0])
        if args.protocol != None:
            arglist.append(args.protocol[0])
        if args.srcport != None:
            arglist.append(args.srcport[0])
        if args.destport != None:
            arglist.append(args.destport[0])
        if args.srcmac != None:
            arglist.append(args.srcmac[0])
        if args.destmac != None:
            arglist.append(args.destmac[0])
        if args.date != None:
            # Month and day
            arglist.append(args.date[0][0:2])
            arglist.append(args.date[0][2:4])
        if args.time != None:
            arglist.append(args.time[0][0:2])
            arglist.append(args.time[0][2:4])


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

        # Packets are constantly received
        packetlist = []
        # List of months for the date argument
        months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
        inet_data, addr = conn.recvfrom(65536) # buffersize
        dst_mac, src_mac, L2_proto, data = L2_frame(inet_data)
        packetlist.append(dst_mac)
        packetlist.append(src_mac)
        proto = ""
        # Ethernet frame ID 8 is IPv4
        if L2_proto == 8:
            (time_to_live, L3_proto, src_IP, dst_IP, data) = L3_packet(data)
            packet_num += 1
            packetlist.append(src_IP)
            packetlist.append(dst_IP)
        # IP Protocol ID 1 is ICMP
        if L3_proto == 1:
            icmp_type, checksum, data = icmp_unpack(data)
            proto = "ICMP"
            packetlist.append(proto)
        # IP protocol ID 6 is TCP
        elif L3_proto == 6:
            (src_port, dst_port, seq, ack, data) = tcp_unpack(data)
            proto = "TCP"
            packetlist.append(src_port)
            packetlist.append(dst_port)
            packetlist.append(proto)
        # IP protocol ID 17 is UDP
        elif L3_proto == 17:
            src_port, dst_port, size, data = udp_unpack(data)
            proto = "UDP"
            packetlist.append(src_port)
            packetlist.append(dst_port)
            packetlist.append(proto)

        packetlist.append(datetime_month)
        packetlist.append(datetime_day)
        packetlist.append(datetime_hour) 
        packetlist.append(datetime_min)
        
        #print(arglist)
        #print(packetlist)


        # If every argument is Null, then packets print normally
        if args.destination == None and args.source == None and args.protocol == None and args.srcport == None and args.destport == None and args.srcmac == None and args.destmac == None and args.date == None and args.time == None:
            print(f"| Num: {packet_num} | Src MAC: {src_mac} | Dest MAC: {dst_mac} ", end='')
   
            # Ethernet frame ID 8 is IPv4
            if L2_proto == 8:
                print(f"| Dest IP: {dst_IP} | Source IP: {src_IP} ", end='')
         
            print(f"| Protocol: {proto} | Src Port: {src_port} | Dest Port: {dst_port} | Date: {months[datetime_month-1]} {datetime_day} | Time: {datetime_hour}:{datetime_min}\n", end='')

        elif set(arglist).issubset(packetlist) == True:
            print(f"| Num: {packet_num} | Src MAC: {src_mac} | Dest MAC: {dst_mac} ", end='')
            
            # Ethernet frame ID 8 is IPv4
            if L2_proto == 8:
                print(f"| Dest IP: {dst_IP} | Source IP: {src_IP} ", end='')
         
            print(f"| Protocol: {proto} | Src Port: {src_port} | Dest Port: {dst_port} | Date: {months[datetime_month-1]} {datetime_day} | Time: {datetime_hour}:{datetime_min}\n", end='')
      


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

if __name__ == '__main__':
    # parser object
    parser = argparse.ArgumentParser(description="A lightweight command-line based Network Traffic Analyzer")

    parser.add_argument("-dest", "--destination", type=str, nargs=1, metavar="destination_ip", default=None, help="Specify your desired Destination IP Address for filtration; Syntax = 111.222.333.444")
    parser.add_argument("-s", "--source", type=str, nargs=1, metavar="source_ip", default=None, help="Specify your desired source IP Address for filtration; Syntax = 111.222.333.444")
    parser.add_argument("-pr", "--protocol", type=str, nargs=1, metavar="protocol_name", default=None, help="Specify your desired protocol name for filtration; TCP or UDP")
    parser.add_argument("-sp", "--srcport", type=str, nargs=1, metavar="src_port_num", default=None, help="Specify your desired Source Port number for filtration")
    parser.add_argument("-dp", "--destport", type=str, nargs=1, metavar="dest_port_num", default=None, help="Specify your desired Destination Port number for filtration")
    parser.add_argument("-sm" , "--srcmac", type=str, nargs=1, metavar="src_mac", default=None, help="Specify your desired Source Mac address for filtration; Syntax = 00:00:00:00:00:00")
    parser.add_argument("-dm" , "--destmac", type=str, nargs=1, metavar="dest_mac", default=None, help="Specify your desired Destination Mac address for filtration; Syntax = 00:00:00:00:00:00")
    parser.add_argument("-d", "--date", type=str, nargs=1, metavar="date", default=None, help="Specify your desired date of packet creation for filtration; Syntax = MMdd")
    parser.add_argument("-t", "--time", type=str, nargs=1, metavar="time", default=None, help="Specify your desired time of packet creation for filtration in 24 hour format; Syntax = HHmm")

    args = parser.parse_args()

    if args.destination != None:
        try:
            ipaddress.IPv4Address(args.destination[0])
        except ipaddress.AddressValueError:  
            sys.exit("Incorrect syntax for Destination IP! Reenter the option with this syntax: 123.123.123.123\nExiting program...")   
    else:
        pass

    if args.source != None:
        try:
            ipaddress.IPv4Address(args.source[0])
        except ipaddress.AddressValueError:  
            sys.exit("Incorrect syntax for Source IP! Reenter the option with this syntax: 123.123.123.123\nExiting program...")   
    else:
        pass

    if args.protocol != None:
        protolist = ["TCP", "UDP", "ICMP"]
        if args.protocol[0] not in protolist:
            sys.exit(f"Protocol not in the list of fliterable protocols. Enter a protocol as it appears in this list: {', '.join(protolist)}")
    else:
        pass

    if args.srcport != None:
        try:
            # Checking valid port number
            if int(args.srcport[0]) not in range(1, 65535):
                sys.exit("Entered Source port argument not found in range 1-65535! Reenter the option within that range\nExiting Program...")
        except ValueError:
            sys.exit("Entered Source port option is not an integer! Reenter as an integer within the range 1-65535\nExiting Program...")
    else:
        pass

    if args.destport != None:
        try:
            # Checking valid port number)
            if int(args.destport[0]) not in range(1, 65535):
                sys.exit("Entered Destination port argument not found in range 1-65535! Reenter the option within that range\nExiting Program...")
        except ValueError:
            sys.exit("Entered Source port option is not an integer! Reenter as an integer within the range 1-65535\nExiting Program...")
    else:
        pass

    if args.srcmac != None:
        # Regex to check valid MAC address
        regex = ("^([0-9A-Fa-f]{2}[:-])" +
                "{5}([0-9A-Fa-f]{2})|" +
                "([0-9a-fA-F]{4}\\." +
                "[0-9a-fA-F]{4}\\." +
                "[0-9a-fA-F]{4})$")
        p = re.compile(regex)
        if (re.search(p, args.srcmac[0])):
            pass
        else:
            sys.exit("Entered Source MAC address argument was not the proper syntax! Reenter MAC address with this syntax: 00:00:00:00:00:00 or 00-00-00-00-00-00\nExiting Program...")
    else:
        pass

    if args.destmac != None:
        # Regex to check valid MAC address
        regex = ("^([0-9A-Fa-f]{2}[:-])" +
                "{5}([0-9A-Fa-f]{2})|" +
                "([0-9a-fA-F]{4}\\." +
                "[0-9a-fA-F]{4}\\." +
                "[0-9a-fA-F]{4})$")
        p = re.compile(regex)
        if (re.search(p, args.srcmac[0])):
            pass
        else:
            sys.exit("Entered Destination MAC address argument was not the proper syntax! Reenter MAC address with this syntax: 00:00:00:00:00:00 or 00-00-00-00-00-00\nExiting Program...")
    else:
        pass

    if args.date != None:
        if len(args.date[0]) == 4:
            if args.date[0] == int:
                pass
        else:
            sys.exit("Entered Date argument is not an integer or was inputted incorrectly! Reenter Date argument with this syntax: MMDD\nExiting Program...")
    else:
        pass

    if args.time != None:
        if len(args.time[0]) == 4:
            if args.time[0] == int:
                pass
        else:
            sys.exit("Entered Time argument is not an integer or was inputted incorrectly! Reenter Time argument with this syntax in a 24 hour format: HHMM\nExiting Program")

    # Executing the Program
    try: 
        monitor(args)

    except KeyboardInterrupt:
        pass

    #printargs(args)
    # To do:
    # You have your output code, this one, and you have a second script which takes a variable from this one and changes it and sends it back to this one
    # both scripts are running at the same time.

    # Think about a hypothetical client that this product is made for. Decide what they will want and how you are going to implement it.

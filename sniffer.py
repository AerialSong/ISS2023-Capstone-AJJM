#!/usr/bin/python3
import argparse
import json
import os
import time as clock
import socket
import datetime
import subprocess
import re
import sys
import ipaddress
import netmon
import shlex

# Prereq install:
# gnome-session
# dbus-x11


PIPEPATH = f'./packetlogs/packetext{datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")}.txt'

# Code by Arthur Kutepov, Jomel Jay 2023
    
# Variations of yes and no in input
yes = ['yes', 'Yes', 'YES', 'Y', 'y']
no = ['no', 'No', "NO", 'N', 'n']

def monitorx(args):
    # Makes a socket connection
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    # Network Packet counter
    packet_num = 0
    format_star1 = "    *"
    format_star2 = "\t*"
    format_tab = "\t   "
    # Path for argument changing json txt file
    path = "arg.txt"

    # Checks if there are less than two arguments entered at the command line
    # If so, it asks user if they would like to enter arguments for filtering
    if len(sys.argv) < 2:
        wantargs = input("Would you like to filter output for any arguments? (Default Value N) Y/N: ")
        if wantargs == '':
            wantargs = 'n'
        if wantargs in yes:
            newargs = input("Please input your desired arguments with the intended syntax: ")
            cmd_args = shlex.split(newargs)
            subprocess.run(["./sniffer.py"] + cmd_args)

    if args.log == None:
        logging = input("Would you like to save a log of your sniffing session with extended details? Warning: File size may be large with sessions with many packets. (Default value N) Y/N: ")
        if logging == '':
            logging = 'n'
    else:
        logging = args.log[0]

    # Checks if args.sleep argument has been filled
    # if not, checks if user would like to make output sleep for a chosen length of seconds after each packet
    if args.sleep == None:
        sleeper = input("How many seconds should the output sleep after printing a packet? (Default value 0): ")
        if sleeper == '':
            sleeper = 0
        if sleeper != '':
            sleeper = float(sleeper)
    else:
        pass

    # Checks if packetlogs directory exists within current directory
    # If not, it will create that directory
    if logging in yes:
        if os.path.exists('./packetlogs') == False:
            os.makedirs('./packetlogs')
        if os.path.exists(PIPEPATH) == False:
            fp = open(PIPEPATH, 'x')
            fp.close()
    elif logging in no:
        pass

    # Checks to see if the terminal option had been flagged
    # If it hasn't, it prompts the user to input an answer
    if args.terminal == None:
        termin = input("Would you like to launch a new root terminal window with which to input new arguments live? (Defualt value N) Y/N: ")
        if termin == '':
            termin = "n"
    else:
        termin = args.terminal[0]
    
    if termin in yes:
        os.system("gnome-terminal")
    elif termin in no:
        pass
        
    
    # local list variable to store json namespace data
    mydict = {}
    while True:
        # Separated the month, day, hour and minute of the current time
        datetime_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        datetime_month = int(datetime.datetime.now().strftime("%m"))#.strftime("%Y-%m-%d %H:%M:%S")
        datetime_day = datetime.datetime.now().strftime('%d')
        datetime_hour = datetime.datetime.now().strftime("%H")
        datetime_min = datetime.datetime.now().strftime("%M")
        # Checks if newly created txt file exists
        # if so, the arguments are then changed in real time
        if os.path.exists(path):
            with open(path, "r") as f:
                mydict = json.load(f)
                f.close()
            os.remove(path)
                   
            # Moves all the values from the json file to mydict
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
            if mydict["clear"] != None:
                args.clear = mydict["clear"]
            if mydict["sleep"] != None:
                args.sleep = mydict["sleep"]
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

        if args.sleep != None and args.sleep[0] == 'none':
            args.sleep = None

        # If the Clear argument from the json file is labelled True, then it will clear
        # every other argument
        if args.clear == True:
            args.destination = None
            args.source = None
            args.protocol = None
            args.srcport = None
            args.destport = None
            args.srcmac = None
            args.destmac = None
            args.date = None
            args.time = None
            args.sleep = None

        # Dictionary keys to compare to packet info
        argdictlist = {"Destination":"", "Source":"", "Protocol":"", "Srcport":"", "Destport":"", "Srcmac":"", "Destmac":"", "Month":"", "Day":"", "Hour":"", "Minute":""}

        if args.destination != None:
            # Destination IP Address
            argdictlist["Destination"] = args.destination[0]
        if args.source != None:
            # Source IP Address
            argdictlist["Source"] = args.source[0]
        if args.protocol != None:
            # Protocol
            args.protocol[0] = args.protocol[0].upper()
            argdictlist["Protocol"] = args.protocol[0]
        if args.srcport != None:
            # Source Port
            argdictlist["Srcport"] = args.srcport[0]
        if args.destport != None:
            # Destination Port
            argdictlist["Destport"] = args.destport[0]
        if args.srcmac != None:
            # Source MAC Address
            argdictlist["Srcmac"] = args.srcmac[0]
        if args.destmac != None:
            # Destination MAC Address
            argdictlist["Destmac"] = args.destmac[0]
        if args.date != None:
            # Month and day
            argdictlist["Month"] = args.date[0][0:2]
            argdictlist["Day"] = args.date[0][2:4]
        if args.time != None:
            argdictlist["Hour"] = args.time[0][0:2]
            argdictlist["Minute"] = args.time[0][2:4]

        # Removes Keys with NONE value type
        clean = {}

        # Removing all values from dictionary that have a key with a value of blank
        argdictlist
        for k, v in argdictlist.items():
            if v != "":
                clean[k] = v

        # Redefine the dictionary with the cleaned one
        argdictlist = clean

        # Packets are constantly received
        packetdictlist = {"Destination":"", "Source":"", "Protocol":"", "Srcport":"", "Destport":"", "Srcmac":"", "Destmac":"", "Month":"", "Day":"", "Hour":"", "Minute":""}

        # List of months for the date argument
        months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
        inet_data, addr = conn.recvfrom(65536) # buffersize
        dst_mac, src_mac, L2_proto, data = netmon.L2_frame(inet_data)
        packetdictlist["Destmac"] = dst_mac
        packetdictlist["Srcmac"] = src_mac
        proto = ""
        
        # Ethernet frame ID 8 is IPv4
        if L2_proto == 8:
            (time_to_live, L3_proto, src_IP, dst_IP, data) = netmon.L3_packet(data)
            url, alias, addresslist = netmon.dns_host_lookup(src_IP)
            packet_num += 1
            packetdictlist["Source"] = src_IP
            packetdictlist["Destination"] = dst_IP
        else:
            (time_to_live, L3_proto, src_IP, dst_IP, data) = netmon.L3_packet(data)
            packet_num += 1

        # IP Protocol ID 1 is ICMP
        if L3_proto == 1:
            icmp_type, checksum, data = netmon.icmp_unpack(data)
            proto = "ICMP"
            packetdictlist["Protocol"] = proto

        # IP protocol ID 6 is TCP
        elif L3_proto == 6:
            src_port, dst_port, seq, ack, data = netmon.tcp_unpack(data)
            proto = "TCP"
            packetdictlist["Srcport"] = src_port
            packetdictlist["Destport"] = dst_port
            packetdictlist["Protocol"] = proto

        # IP protocol ID 17 is UDP
        elif L3_proto == 17:
            src_port, dst_port, size, data = netmon.udp_unpack(data)
            proto = "UDP"
            packetdictlist["Srcport"] = src_port
            packetdictlist["Destport"] = dst_port
            packetdictlist["Protocol"] = proto
        else:
            proto = L3_proto

        # Adds a leading zero to the month
        packetdictlist["Month"] = str(datetime_month).zfill(2)
        packetdictlist["Day"] = datetime_day
        packetdictlist["Hour"] = datetime_hour
        packetdictlist["Minute"] = datetime_min

        # Turn dictionaries into sets
        argdictset = set(argdictlist.items())
        packetdictset = set(packetdictlist.items())

        if args.sleep != None:
            sleeper = args.sleep[0]


        # If every argument is Null, then packets print normally
        if args.destination == None and args.source == None and args.protocol == None and args.srcport == None and args.destport == None and args.srcmac == None and args.destmac == None and args.date == None and args.time == None:
            # Sends extended packet details to a txt file, named accordingly by date and time, for advanced analysis
            if logging in yes:
                if L2_proto == 8:
                    f = open(PIPEPATH, 'a+')
                    # ICMP
                    if L3_proto == 1:
                        f.write("Number %d | Date and time: %s\n" % (packet_num, datetime_now) + format_star1 + "Ethernet Frame %d - Dst MAC: %s, Src MAC: %s, Ethernet Protocol ID: %d\n" % (packet_num, dst_mac, src_mac, L2_proto) + format_star1 + "IPv4 Packet - Src IP: %s, Dst IP: %s, IP Protocol ID: %d, TTL: %d, URL: %s\n" % (src_IP, dst_IP, L3_proto, time_to_live, url) + format_star1 + "ICMP Packet - Type: %s, Checksum: %d\n" % (icmp_type, checksum) + format_star2 + "Data:\n" + netmon.line_format(format_tab, data) + '\n')
                    #TCP
                    elif L3_proto == 6:
                        f.write("Number %d | Date and time: %s\n" % (packet_num, datetime_now) + format_star1 + "Ethernet Frame %d - Dst MAC: %s, Src MAC: %s, Ethernet Protocol ID: %d\n" % (packet_num, dst_mac, src_mac, L2_proto) + format_star1 + "IPv4 Packet - Src IP: %s, Dst IP: %s, IP Protocol ID: %d, TTL: %d, URL: %s\n" % (src_IP, dst_IP, L3_proto, time_to_live, url) + format_star1 + "TCP Segment - Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d\n" % (src_port, dst_port, seq, ack) + format_star2 + "Data:\n" + netmon.line_format(format_tab, data) + '\n')
                    #UDP
                    elif L3_proto == 17:
                        f.write("Number %d | Date and time: %s\n" % (packet_num, datetime_now) + format_star1 + "Ethernet Frame %d - Dst MAC: %s, Src MAC: %s, Ethernet Protocol ID: %d\n" % (packet_num, dst_mac, src_mac, L2_proto) + format_star1 + "IPv4 Packet - Src IP: %s, Dst IP: %s, IP Protocol ID: %d, TTL: %d, URL: %s\n" % (src_IP, dst_IP, L3_proto, time_to_live, url) + format_star1 + "UDP Segment - Src Port: %d, Dst Port: %d, Size: %d\n" % (src_port, dst_port, size) + format_star2 + "Data:\n" + netmon.line_format(format_tab, data) + '\n')
                    else:
                        f.write("Number %d | Date and time: %s\n" % (packet_num, datetime_now) + format_star1 + "Ethernet Frame %d - Dst MAC: %s, Src MAC: %s, Ethernet Protocol ID: %d\n" % (packet_num, dst_mac, src_mac, L2_proto) + format_star1 + "IPv4 Packet - Src IP: %s, Dst IP: %s, IP Protocol ID: %d, TTL: %d, URL: %s\n" % (src_IP, dst_IP, L3_proto, time_to_live, url) + "\n" + format_star2 + "Data:\n" + netmon.line_format(format_tab, data) + '\n')
                    f.close()
            elif logging in no:
                pass
            print(f"| Num: {packet_num} | Src MAC: {src_mac} | Dest MAC: {dst_mac} ", end='')
   
            # Ethernet frame ID 8 is IPv4
            if L2_proto == 8:
                if url != None:
                    print(f"| Dest IP: {dst_IP} | Source IP: {src_IP} | URL: {url} ", end='')
                else:
                    print(f"| Dest IP: {dst_IP} | Source IP: {src_IP} ", end='')
            
            # If ethernet frame is not IPv4
            else:
                print(f"| L3 protocol ID: {L3_proto} ", end='')
                
            # If the Layer 3 protocol is not ICMP, TCP or UDP it will not print these
            if L3_proto == 1 or L3_proto == 6 or L3_proto == 17:
                print(f"| Protocol: {proto} | Src Port: {src_port} | Dest Port: {dst_port} ", end='')
            
            print(f"|Date: {months[datetime_month-1]} {datetime_day} | Time: {datetime_hour}:{datetime_min}\n", end='')
            clock.sleep(sleeper)

        elif argdictset.issubset(packetdictset) == True:
            # Sends extended packet details to a txt file, named accordingly by date and time, for advanced analysis
            if logging in yes:
                if L2_proto == 8:
                    f = open(PIPEPATH, 'a+')
                    # ICMP
                    if L3_proto == 1:
                        f.write("Number %d | Date and time: %s\n" % (packet_num, datetime_now) + format_star1 + "Ethernet Frame %d - Dst MAC: %s, Src MAC: %s, Ethernet Protocol ID: %d\n" % (packet_num, dst_mac, src_mac, L2_proto) + format_star1 + "IPv4 Packet - Src IP: %s, Dst IP: %s, IP Protocol ID: %d, TTL: %d, URL: %s\n" % (src_IP, dst_IP, L3_proto, time_to_live, url) + format_star1 + "ICMP Packet - Type: %s, Checksum: %d\n" % (icmp_type, checksum) + format_star2 + "Data:\n" + netmon.line_format(format_tab, data) + '\n')
                    #TCP
                    elif L3_proto == 6:
                        f.write("Number %d | Date and time: %s\n" % (packet_num, datetime_now) + format_star1 + "Ethernet Frame %d - Dst MAC: %s, Src MAC: %s, Ethernet Protocol ID: %d\n" % (packet_num, dst_mac, src_mac, L2_proto) + format_star1 + "IPv4 Packet - Src IP: %s, Dst IP: %s, IP Protocol ID: %d, TTL: %d, URL: %s\n" % (src_IP, dst_IP, L3_proto, time_to_live, url) + format_star1 + "TCP Segment - Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d\n" % (src_port, dst_port, seq, ack) + format_star2 + "Data:\n" + netmon.line_format(format_tab, data) + '\n')
                    #UDP
                    elif L3_proto == 17:
                        f.write("Number %d | Date and time: %s\n" % (packet_num, datetime_now) + format_star1 + "Ethernet Frame %d - Dst MAC: %s, Src MAC: %s, Ethernet Protocol ID: %d\n" % (packet_num, dst_mac, src_mac, L2_proto) + format_star1 + "IPv4 Packet - Src IP: %s, Dst IP: %s, IP Protocol ID: %d, TTL: %d, URL: %s\n" % (src_IP, dst_IP, L3_proto, time_to_live, url) + format_star1 + "UDP Segment - Src Port: %d, Dst Port: %d, Size: %d\n" % (src_port, dst_port, size) + format_star2 + "Data:\n" + netmon.line_format(format_tab, data) + '\n')
                    else:
                        f.write("Number %d | Date and time: %s\n" % (packet_num, datetime_now) + format_star1 + "Ethernet Frame %d - Dst MAC: %s, Src MAC: %s, Ethernet Protocol ID: %d\n" % (packet_num, dst_mac, src_mac, L2_proto) + format_star1 + "IPv4 Packet - Src IP: %s, Dst IP: %s, IP Protocol ID: %d, TTL: %d, URL: %s\n" % (src_IP, dst_IP, L3_proto, time_to_live, url) + "\n" + format_star2 + "Data:\n" + netmon.line_format(format_tab, data) + '\n')
                    f.close()
            elif logging in no:
                pass
            print(f"| Num: {packet_num} | Src MAC: {src_mac} | Dest MAC: {dst_mac} ", end='')
   
            # Ethernet frame ID 8 is IPv4
            if L2_proto == 8:
                if url != None:
                    print(f"| Dest IP: {dst_IP} | Source IP: {src_IP} | URL: {url} ", end='')
                else:
                    print(f"| Dest IP: {dst_IP} | Source IP: {src_IP} ", end='')
            
            # If ethernet frame is not IPv4
            else:
                print(f"| L3 protocol ID: {L3_proto} ", end='')
                
            # If the Layer 3 protocol is not ICMP, TCP or UDP it will not print these
            if L3_proto == 1 or L3_proto == 6 or L3_proto == 17:
                print(f"| Protocol: {proto} | Src Port: {src_port} | Dest Port: {dst_port} ", end='')
            
            print(f"|Date: {months[datetime_month-1]} {datetime_day} | Time: {datetime_hour}:{datetime_min}\n", end='')
            clock.sleep(sleeper)


# parser object
parser = argparse.ArgumentParser(description="A lightweight command-line based Network Packet Sniffer")

# All arguments and their details
parser.add_argument("-dest", "--destination", type=str, nargs=1, metavar="dest_ip", default=None, help="Specify your desired Destination IP Address for filtration; Syntax = 111.222.333.444")
parser.add_argument("-s", "--source", type=str, nargs=1, metavar="source_ip", default=None, help="Specify your desired Source IP Address for filtration; Syntax = 111.222.333.444")
parser.add_argument("-pr", "--protocol", type=str, nargs=1, metavar="protocol_name", default=None, help="Specify your desired Protocol name for filtration; TCP, UDP, ICMP")
parser.add_argument("-sp", "--srcport", type=str, nargs=1, metavar="src_port_num", default=None, help="Specify your desired Source Port number for filtration, from 1-65535")
parser.add_argument("-dp", "--destport", type=str, nargs=1, metavar="dest_port_num", default=None, help="Specify your desired Destination Port number for filtration, from 1-65535")
parser.add_argument("-sm" , "--srcmac", type=str, nargs=1, metavar="src_mac", default=None, help="Specify your desired Source Mac address for filtration, Case Sensitive; Syntax = 0A:0A:0A:0A:0A:0A")
parser.add_argument("-dm" , "--destmac", type=str, nargs=1, metavar="dest_mac", default=None, help="Specify your desired Destination Mac address for filtration, Case Sensitive; Syntax = 0A:0A:0A:0A:0A:0A")
parser.add_argument("-d", "--date", type=str, nargs=1, metavar="date", default=None, help="Specify your desired date of packet creation for filtration; Syntax = MMdd")
parser.add_argument("-t", "--time", type=str, nargs=1, metavar="time", default=None, help="Specify your desired time of packet creation for filtration in 24 hour format; Syntax = HHmm")
parser.add_argument("-sl", "--sleep", type=float, nargs=1, metavar="sleep_sec", default=None, help="Specify how many seconds you would like the output to sleep upon printing a packet; for an easier to follow output.")
parser.add_argument("-log", type=str, nargs=1, metavar="log_pick", default=None, help="Specify whether or not you'd like to log your capture session in a txt file.")
parser.add_argument("-term", "--terminal", type=str, nargs=1, metavar="termpick", default=None, help="Specify whether you would like a terminal to spawn with which to update arguments live with, using linput.py.")
parser.add_argument("-c", "--clear", action="store_true", help="Clear all already entered arguments//Use in linput.py")

args = parser.parse_args()

# Syntax catching for each argument
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
    if str(args.protocol[0]).isupper == False:
        args.protocol[0] = str(args.protocol[0]).upper()
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
    regex = ("^([0-9A-F]{2}[:-])" +
            "{5}([0-9A-F]{2})|" +
            "([0-9A-F]{4}\\." +
            "[0-9A-F]{4}\\." +
            "[0-9A-F]{4})$")
    p = re.compile(regex)
    if (re.search(p, args.srcmac[0])):
        pass
    else:
        sys.exit("Entered Source MAC address argument was not the proper syntax! Reenter MAC address with this syntax, Case Sensitive: 0A:0A:0A:0A:0A:0A or 0A-0A-0A-0A-0A-0A\nExiting Program...")
else:
    pass

if args.destmac != None:
    # Regex to check valid MAC address
    regex = ("^([0-9A-F]{2}[:-])" +
            "{5}([0-9A-F]{2})|" +
            "([0-9A-F]{4}\\." +
            "[0-9A-F]{4}\\." +
            "[0-9A-F]{4})$")
    p = re.compile(regex)
    if (re.search(p, args.destmac[0])):
        pass
    else:
        sys.exit("Entered Destination MAC address argument was not the proper syntax! Reenter MAC address with this syntax, Case Sensitive: 0A:0A:0A:0A:0A:0A or 0A-0A-0A-0A-0A-0A\nExiting Program...")
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

if args.log != None:
    if args.log[0] not in no and args.log[0] not in yes:
        sys.exit("Entered argument is not a valid! Please enter yes or no.\nExiting Program...")
    else:
        pass

if args.terminal != None:
    if args.terminal[0] not in no and args.terminal[0] not in yes:
        sys.exit("Entered argument is not a valid! Please enter yes or no.\nExiting Program...")
    else:
        pass

# Executing the Program
try: 
    monitorx(args)

except KeyboardInterrupt:
    pass

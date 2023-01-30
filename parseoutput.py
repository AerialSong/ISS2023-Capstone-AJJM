import argparse
import subprocess
import socket
import sys
import time as clock
import re
import keyboard

# Print function. All arguments are sent here and printed
def printargs():
    try:
        while True:
            if args.destination != None:
                print(f"Destination IP is {args.destination[0]}")
            if args.source != None:
                print(f"Source IP is {args.source[0]}")
            if args.protocol != None:
                print(f"Protocol type is {args.protocol[0]}")
            if args.port != None:
                print(f"Port number is {args.port[0]}")
            if args.date != None:
                print(f"Date of packet capture is {args.date[0]}")
            if args.time != None:
                print(f"Time of packet capture is {args.time[0]}")
            clock.sleep(1)
            print("\n")
        
    except KeyboardInterrupt:
        print("Exiting Program...")
        sys.tracebacklimit = 0

# parser object
parser = argparse.ArgumentParser(description="A lightweight command-line based Network Traffic Analyzer")

parser.add_argument("-des", "--destination", "-dest", type=str, nargs=1, metavar="destination_ip", default=None, help="Destination IP Address")
parser.add_argument("-s", "--source", type=str, nargs=1, metavar="source_ip", default=None, help="Source IP Address")
parser.add_argument("-pr", "--protocol", type=str, nargs=1, metavar="protocol_name", default=None, help="Type of protocol")
parser.add_argument("-p", "--port", type=str, nargs=1, metavar="port_num", default=None, help="Port Number")
parser.add_argument("-d", "--date", type=int, nargs=1, metavar="date", default=None, help="Date packet was made; Syntax = MMdd")
parser.add_argument("-t", "--time", type=str, nargs=1, metavar="time", default=None, help="Time packet was made; Syntax = HHmm")

args = parser.parse_args()

printargs()

# TEST THE OPTIONS: For each option, print a while loop, then see if you can enter an input during the while loop

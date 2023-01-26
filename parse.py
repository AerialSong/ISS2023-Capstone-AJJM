import os
import argparse
import threading
import time as clock
import itertools
import queue
import re

def destination(arg):
    print(f"Destination IP is {arg[0]}")
    return

def source(arg):
    print(f"Source IP is {arg[0]}")
    return

def protocol(arg):
    print(f"Protocol type is {arg[0]}")
    return

def port(arg):
    print(f"Port number is {arg[0]}")
    return

def date(arg):
    print(f"Date of packet capture is {arg[0]}")
    return

def time(arg):
    print(f"Time of packet capture is {arg[0]}")
    #currenttime = clock.strftime("%H:%M")
    #print(f"Current time is {currenttime}")
    return

# parser object
parser = argparse.ArgumentParser(description="A lightweight command-line based Network Traffic Analyzer")

parser.add_argument("-des", "--destination", "-dest", type=str, nargs=1, metavar="destination_ip", default=None, help="Destination IP Address")
parser.add_argument("-s", "--source", type=str, nargs=1, metavar="source_ip", default=None, help="Source IP Address")
parser.add_argument("-pr", "--protocol", type=str, nargs=1, metavar="protocol_name", default=None, help="Type of protocol")
parser.add_argument("-p", "--port", type=str, nargs=1, metavar="port_num", default=None, help="Port Number")
parser.add_argument("-d", "--date", type=int, nargs=1, metavar="date", default=None, help="Date packet was made; Syntax = MMdd")
parser.add_argument("-t", "--time", type=str, nargs=1, metavar="time", default=None, help="Time packet was made; Syntax = HHmm")

args = parser.parse_args()

if args.destination != None:
    destination(args.destination)
if args.source != None:
    source(args.source)
if args.protocol != None:
    protocol(args.protocol)
if args.port != None:
    port(args.port)
if args.date != None:
    date(args.date)
if args.time != None:
    time(args.time)

# TEST THE OPTIONS: For each option, print a while loop, then see if you can enter an input during the while loop
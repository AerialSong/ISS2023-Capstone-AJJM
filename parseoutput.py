import argparse
import json
import os
from os.path import exists
import sys
import time as clock

# Code by Arthur Kutepov, 2023
'''
def variablechange(arg):
    try:
        arg[0] = input(f"What would you like to change the value of {arg[0]} to? ")
        printargs(arg)
    except EOFError or KeyboardInterrupt:
        print("\nExiting Program...")
'''

'''
def destination(arg):
        try:
            while True:
                print(f"Destination IP is {arg.destination[0]}")
                clock.sleep(0.5)
        except KeyboardInterrupt:
            variablechange(arg)
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

'''

# Print function. All arguments are sent here and printed
def printargs(args):
    path = "arg.txt"
    try:
        while True:
            # Checks if newly created txt file exists
            # if so, the arguments are then changed in real time
            if exists(path):
                with open(path, "r") as f:
                    args.__dict__ = json.load(f)
                    f.close()
                os.remove(path)
            if args.destination != None:
                print(f"Dest IP: {args.destination[0]}, ", end='')
            if args.source != None:
                print(f"Source IP: {args.source[0]}, ", end='')
            if args.protocol != None:
                print(f"Protocol: {args.protocol[0]}, ", end='')
            if args.port != None:
                print(f"Port: {args.port[0]}, ", end='')
            if args.date != None:
                print(f"Date: {args.date[0]}, ", end='')
            if args.time != None:
                print(f"Time: {args.time[0]}", end='')
            clock.sleep(1)
            print("\n")
        
    except KeyboardInterrupt:
        print("\nExiting Program...\n")
        sys.tracebacklimit = 0
    '''
    send variables to arguments.py
    arguments.py changes up the variables that the user wants to change and sends them back
    arguments are changed before the next while loop occurs
    '''


# parser object
parser = argparse.ArgumentParser(description="A lightweight command-line based Network Traffic Analyzer")

parser.add_argument("-des", "--destination", "-dest", type=str, nargs=1, metavar="destination_ip", default=None, help="Destination IP Address")
parser.add_argument("-s", "--source", type=str, nargs=1, metavar="source_ip", default=None, help="Source IP Address")
parser.add_argument("-pr", "--protocol", type=str, nargs=1, metavar="protocol_name", default=None, help="Type of protocol")
parser.add_argument("-p", "--port", type=str, nargs=1, metavar="port_num", default=None, help="Port Number")
parser.add_argument("-d", "--date", type=int, nargs=1, metavar="date", default=None, help="Date packet was made; Syntax = MMdd")
parser.add_argument("-t", "--time", type=str, nargs=1, metavar="time", default=None, help="Time packet was made; Syntax = HHmm")

args = parser.parse_args()

printargs(args)
'''
if args.destination != None:
    destination(args)
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
'''
# To do:
# For each option, print a while loop, then see if you can enter an input during the while loop
# Import netMonitor as a module and see if you can capture any network info
# Decide if you want multiple scripts or a single script. Multiple scripts would be less resource intensive
# You have your output code, this one, and you have a second script which takes a variable from this one and changes it and sends it back to this one
# both scripts are running at the same time.

# Figure out how to change strings into namespace objects : DONE

# Think about a hypothetical client that this product is made for. Decide what they will want and how you are going to implement it.

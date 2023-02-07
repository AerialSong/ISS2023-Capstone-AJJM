import argparse
import json
import os
from os.path import exists
import sys
import time as clock

# Code by Arthur Kutepov, 2023

# Print function. All arguments are sent here and printed
def printargs(args):
    path = "arg.txt"
    
    # local list variable to store json namespace data
    mydict = {}
    try:
        while True:
            # Checks if newly created txt file exists
            # if so, the arguments are then changed in real time
            if exists(path):
                with open(path, "r") as f:
                    #args.__dict__ = json.load(f)
                    mydict = json.load(f)
                    f.close()
                    #print(mydict)
                os.remove(path)
                     
                if mydict["destination"] != None:
                    args.destination = mydict["destination"]
                if mydict["source"] != None:
                    args.source = mydict["source"]
                if mydict["protocol"] != None:
                    args.protocol = mydict["protocol"]
                if mydict["port"] != None:
                    args.port = mydict["port"]
                if mydict["date"] != None:
                    args.date = mydict["date"]
                if mydict["time"] != None:
                    args.time = mydict["time"]
                '''for key, value in mydict.items():
                    if value != None and key == vars(args).keys:
                        vars(args).value = value'''
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

            if args.port != None and args.port[0] != 'none':
                print("|", end='')
                print(f" Port: {args.port[0]} ", end='')
            elif args.port != None and args.port[0] == 'none':
                args.port = None

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
        sys.tracebacklimit = 0

if __name__ == '__main__':
    # parser object
    parser = argparse.ArgumentParser(description="A lightweight command-line based Network Traffic Analyzer")

    parser.add_argument("-dest", "--destination", type=str, nargs=1, metavar="destination_ip", default=None, help="Destination IP Address")
    parser.add_argument("-s", "--source", type=str, nargs=1, metavar="source_ip", default=None, help="Source IP Address")
    parser.add_argument("-pr", "--protocol", type=str, nargs=1, metavar="protocol_name", default=None, help="Type of protocol")
    parser.add_argument("-p", "--port", type=str, nargs=1, metavar="port_num", default=None, help="Port Number")
    parser.add_argument("-d", "--date", type=str, nargs=1, metavar="date", default=None, help="Date packet was made; Syntax = MMdd")
    parser.add_argument("-t", "--time", type=str, nargs=1, metavar="time", default=None, help="Time packet was made; Syntax = HHmm")

    args = parser.parse_args()

    printargs(args)
    # To do:
    # Import netMonitor as a module and see if you can capture any network info
    # You have your output code, this one, and you have a second script which takes a variable from this one and changes it and sends it back to this one
    # both scripts are running at the same time.

    # Think about a hypothetical client that this product is made for. Decide what they will want and how you are going to implement it.

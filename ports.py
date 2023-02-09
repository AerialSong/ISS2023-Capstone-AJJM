#!/usr/bin/bash

import socket
import sys
import re
import time
from datetime import datetime

# Code by Mackenzie Cleland, 2023
# This code comprises a fully-functional port scanner, as part of our capstone project,
# SCOLIA v.1.0 All-in-One IDS Suite

# IMPORTANT!!!
# The config file MUST be formatted as follows:
# Line 1 = Host IP address
# Line 2 = LOWER port limit
# Line 3 = UPPER port limit
# Any deviation from this format WILL cause issues!!!

# subprocess.call('clear', shell=True)    # Clears

# IP and upper/lower port limits need not be defined globally, as they actually don't need to be passed directly
# genConfig() generates them in the first place, and pipes them to config.txt
# readConfig() reads those same values from config.txt, so variable names don't matter
# hostScan() does an entirely-customized scan, so again, variable names don't matter


def scanHost(address, low, up):  # Scans specified IP address and ports, either from config.txt or according to user specifications
    timea = datetime.now()

    print("Starting port scanning operation...")    # Prompt
    time.sleep(3)
    print(f"Scanning ports {low} - {up - 1}...")
    try:
        for p in range(low, up):
            csocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # This syntax may be Unix-exclusive (?)
            cconn = csocket.connect_ex((address, p))
            if cconn == 0:
                print(f"Port {p} is open!")
            else:
                print(f"Port {p} is closed!")
            csocket.close()
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Exiting program.")
        sys.exit()
    except socket.gaierror:
        print("Critical Error: Failed to resolve hostname. Exiting program.")
        sys.exit()
    except socket.error():
        print("Critical Error: Failed to connect to server. Exiting program.")
        sys.exit()

    timeb = datetime.now()
    total = timeb - timea
    print(f"Completed scan of ports {low} - {up - 1} on server with IP address {address}")
    print(f"Total time elapsed: {total}")


def genConfig():    # Generates config.txt for purposes of automation
    genflow = 0     # Flow control for outer loop
    while genflow == 0:
        confip = input("Please provide IP of server you wish to scan: ")
        confolim = input("Please provide lower port limit for scan: ")
        confulim = input("Please provide upper port limit for scan: ")
        print("Your config file will have the following parameters:")
        print(f"IP = \t\t\t{confip}\nLower port limit = \t{confolim}\nUpper port limit = \t{confulim}")
        yesno = input("Is this OK? Y/N ")
        while True:
            if yesno == "Y" or yesno == "y":    # Will proceed to write to file
                # Put code here!
                # Check in program folder (saves time for user) for config.txt
                # If not there, use bash commands to touch file
                # If there, use bash commands to overwrite file
                # Pipe output to file
                # Start by making file manually, then running script
                # Then delete file, and get script to touch and pipe it!
                genflow = genflow + 1   # Facilitates breaking out of both loops
                break
            elif yesno == "N" or yesno == "n":  # Will trigger outer loop to restart
                print("Please enter parameters again.")
                break
            else:   # Will also trigger outer loop to restart
                print("Improper input entered. Please choose again.")
                break


def readConfig():   # Reads from config.txt and scans based on its parameters
    try:
        with open("config.txt") as f:
            part = f.readlines()
            host = (part[0].strip())
            lower = int(part[1].strip())
            upper = int(part[2].strip()) + 1
            
            print(f"Host IP:\t{host}")  # For debugging
            print(f"Lower:\t\t{lower}")
            print(f"Upper:\t\t{upper - 1}")

            f.close()
            scanHost(host, lower, upper)

    except FileNotFoundError:
        print("Critical Error: Config file not found. Exiting program...")
        sys.exit()


def custScan():     # Establishes IP address and port limits for a custom scan
    while True:  # Retrieves IP address to be scanned
        ipaddr = input("Please provide IP address of server to be scanned: ")
        if not re.match(r'\d+(?:\.\d+){3}', ipaddr):  # Regex to match up IP syntax
            print("Invalid IP address. Please try again.")
        else:
            break

    while True:
        ulim = int(input("Please provide the *HIGHEST* port number you wish to scan: ")) + 1
        if ulim > 65536 or ulim < 1:
            print("Invalid port number. Please try again.")
            sys.exit()
        else:
            break

    while True:
        olim = int(input("Please provide the *LOWEST* port number you wish to scan: "))  # TypeError handling?
        if olim > 65536 or olim < 1 or olim > ulim:
            print("Invalid port number. Please try again.")
            sys.exit()
        else:
            break
    
    scanHost(ipaddr, ulim, olim)


def main():     # Main flow control for program
    while True:
        print("Which operation do you wish to carry out?")
        choice = int(input("1. Write to config.txt\n2. Read from config.txt and scan\n3. Custom scan\n"))
        if choice == 1:
            genConfig()
            break
        elif choice == 2:
            readConfig()
            break
        elif choice == 3:
            custScan()
            break       # Breaks out of main loop
        else:
            print("Invalid choice selected. Please try again.")


main()


# TO DO:
# Implement config file generation
# Implement better error handling for scanning than just exiting, if possible

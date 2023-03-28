#!/usr/bin/bash

import socket
import sys
import re
import time
import os
import platform
import scapy.all as scapy
from datetime import datetime

# Code by Mackenzie Cleland, 2023
# This code comprises a fully-functional port scanner, as part of our capstone project,
# SCORIA v.1.0 All-in-One IDS Suite

# IMPORTANT!!!
# The config file MUST be formatted as follows:
# Line 1 = Host IP address
# Line 2 = LOWER port limit
# Line 3 = UPPER port limit
# Line 4 = ARP/Banner option
#   1 = Banners only;
#   2 = ARP only;
#   3 = ARP/Banners;
#   4 = No additional checks
# Any deviation from this format WILL cause issues!!!

# Special thanks to Isaac Privett, for his advice on extending the functionality of this script

# TERTIARY FIXES:
# Implement non-contiguous port range selection


def scanHost(address, low, up, aflag):  # Scans specified IP address and ports, either from config.txt or according to user specifications
    timea = datetime.now()

    # Actual scanning process
    print("Starting port scanning operation...")
    time.sleep(3)
    print(f"Scanning ports {low} - {up - 1}...")
    try:
        for p in range(low, up):
            csocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cconn = csocket.connect_ex((address, p))
            if cconn == 0:
                print(f"Port {p} is open!")
            else:
                print(f"Port {p} is closed!")
            csocket.close()
            if aflag == 1 or aflag == 3:  # Banner-grabber check
                try:
                    cbanner = str(cconn.recv(1024))
                    print(f'\tPort {p} has banner "{cbanner}"')
                except:
                    print("\tNo banners active on this port.")
            if aflag == 2 or aflag == 3:  # ARP table check
                table = scapy.ARP()
                print(f"\tFor port {p}, {table.summary()}")
            print("")  # For cosmetic reasons (makes output more legible)
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Exiting program.")
        sys.exit()
    except socket.gaierror:
        print("Critical Error: Failed to resolve hostname. Exiting program.")
        sys.exit()
    except socket.herror():
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
        conflag = input("Please select from the following options:\n1. Check for banners only\n2. Check for ARP only\n3. Check for ARP and banners\n4. No additional checks\n")
        print("Your config file will have the following parameters:")
        print(f"IP = \t\t\t{confip}\nLower port limit = \t{confolim}\nUpper port limit = \t{confulim}\nARP/Banners = \t\tOption {conflag}\n")
        yesno = input("Is this OK? Y/N \n")
        while True:
            if yesno == "Y" or yesno == "y":    # Will proceed to write to file
                new = f"{confip}\n{confolim}\n{confulim}\n{conflag}"  # String holds user-defined parameters
                print(f"Operating system detected as: {platform.system()}")  # Check in Scoria installation folder (saves time for user) for config.txt
                print(f"Checking installation directory: {os.getcwd()} for config.txt...")

                try:  # Check if user wants to overwrite config.txt if already present in installation folder
                    open("config.txt")
                    dec = input("File config.txt already exists. Do you wish to overwrite? Y/N \n")
                    if dec == "Y" or dec == "y":  # Overwrite config.txt
                        over = open(os.path.join(os.getcwd(), "config.txt"), "w")
                        over.write(new)
                        over.close()
                        print("File config.txt has been overwritten. Closing program...")
                        sys.exit()

                    elif dec == "N" or dec == "n":  # Return to launcher.py
                        print("Decided not to overwrite config.txt. Closing program...")
                        sys.exit()

                    else:
                        print("Incorrect input! Try again.\n")
                        break

                except FileNotFoundError:  # Touch config.txt if not present in installation folder
                    dec = input("File config.txt can be created. Do you wish to proceed? Y/N")
                    if dec == "Y" or dec == "y":  # Touch config.txt
                        conf = open(os.path.join(os.getcwd(), "config.txt"), "w")
                        conf.write(new)
                        conf.close()
                        print("File config.txt has been generated. Closing program...")
                        sys.exit()

                    elif dec == "N" or dec == "n": # Return to launcher.py
                        print("Decided not to create config.txt. Closing program...")
                        sys.exit()

                    else:
                        print("Incorrect input! Try again.\n")
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
            flag = int(part[3].strip())
            
            print(f"Host IP:\t{host}")  # For debugging
            print(f"Lower:\t\t{lower}")
            print(f"Upper:\t\t{upper - 1}")
            print(f"ARP/Banners:\tOption {flag}")

            f.close()
            scanHost(host, lower, upper, flag)

    except FileNotFoundError:
        print("Critical Error: Config file not found. Exiting program...")
        sys.exit()


def custScan():  # Establishes IP address and port limits for a custom scan
    while True:  # Retrieves IP address to be scanned
        ipaddr = input("Please provide IP address of server to be scanned: ")
        if not re.match(r'\d+(?:\.\d+){3}', ipaddr):  # Regex to match up IP syntax
            print("Invalid IP address. Please try again.")
        else:
            break

    while True:
        ulim = int(input("Please provide the *HIGHEST* port number you wish to scan: ")) + 1
        if ulim > 65536 or ulim < 1:
            print("Invalid port number. Please try again.\n")
        else:
            break

    while True:
        olim = int(input("Please provide the *LOWEST* port number you wish to scan: "))
        if olim > 65536 or olim < 1 or olim > ulim:
            print("Invalid port number. Please try again.")
        else:
            break

    aflag = 0  # Flag determining whether or not ARP table and/or banners will be scanned: 0 = neither; 1 = banners only; 2 = ARP table only; 3 = both

    # Preliminary options for banner and ARP table scanning functionality
    while True:
        prompta = input("Would you like to grab banners from each port? Y/N\n")
        if prompta == "Y" or prompta == "y":
            print("Banners will be grabbed for each port.")
            aflag = aflag + 1  # aflag = 1
            break
        elif prompta == "N" or prompta == "n":
            print("Banners will not be grabbed for any ports.")
            break
        else:
            print("Error: Improper input detected. Please try again.")

    while True:
        promptb = input("Would you like to scan each port for its ARP table? Y/N\n")
        if promptb == "Y" or promptb == "y":
            print("ARP tables will be scanned for each port.")
            aflag = aflag + 2  # This will result in aflag = 2 or aflag = 3, depending on the previous user input; either way, it should be correct.
            break
        elif promptb == "N" or promptb == "n":
            print("ARP tables will not be scanned for any port.")
            break
        else:
            print("Error: Improper input detected. Please try again.")
            
    scanHost(ipaddr, olim, ulim, aflag)


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


if "__name__" == "__main__":  # Allows launcher to import ports.py without immediately trying to run it.
    main()

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
# Any deviation from this format WILL cause issues!!!

# IP and upper/lower port limits need not be defined globally, as they actually don't need to be passed directly
# genConfig() generates them in the first place, and pipes them to config.txt
# readConfig() reads those same values from config.txt, so variable names don't matter
# hostScan() does an entirely-customized scan, so again, variable names don't matter

# Special thanks to Isaac Privett, for his advice on extending the functionality of this script


def scanHost(address, low, up):  # Scans specified IP address and ports, either from config.txt or according to user specifications
    timea = datetime.now()
    aflag = 0  # Flag determining whether or not ARP table and/or banners will be scanned: 0 = neither; 1 = banners only; 2 = ARP table only; 3 = both

    # Preliminary options for banner and ARP table scanning functionality
    while True:
        prompta = input("Would you like to scan each port for its banners? Y/N\n")
        if prompta == "Y" or prompta == "y":
            print("Banners will be scanned for each port.")
            aflag = aflag + 1  # aflag = 1
            break
        elif prompta == "N" or prompta == "n":
            print("Banners will not be scanned for any ports.")
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

    # Actual scanning process
    # Note to self: If breaking up the parameter checks into their own function, remember to include variable bflag in this section as a placeholder/prototype!
    print("Starting port scanning operation...")
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
            # Put banner check here?
            if aflag == 2 or aflag == 3:  # ARP table check
                table = scapy.ARP()
                print(f"    For port {p}, {table.summary()}")
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
        print("Your config file will have the following parameters:")
        print(f"IP = \t\t\t{confip}\nLower port limit = \t{confolim}\nUpper port limit = \t{confulim}")
        yesno = input("Is this OK? Y/N ")
        while True:
            if yesno == "Y" or yesno == "y":    # Will proceed to write to file
                new = f"{confip}\n{confolim}\n{confulim}"  # String holds user-defined parameters
                print(f"Operating system detected as: {platform.system()}")  # Check in Scoria installation folder (saves time for user) for config.txt
                print(f"Checking installation directory: {os.getcwd()} for config.txt...")

                try:  # Check if user wants to overwrite config.txt if already present in installation folder
                    open("config.txt")
                    dec = input("File config.txt already exists. Do you wish to overwrite? Y/N")
                    if dec == "Y" or dec == "y":  # Overwrite config.txt
                        over = open(os.path.join(os.getcwd(), "config.txt"), "w")
                        over.write(new)
                        over.close()
                        print("File config.txt has been overwritten. Returning to launcher.")
                        exec(open("launcher.py").read())

                    elif dec == "N" or dec == "n":  # Return to launcher.py
                        print("Decided not to overwrite config.txt. Returning to Scoria launcher...")
                        print("=================================================================\n")
                        exec(open("launcher.py").read())

                    else:
                        print("Incorrect input! Try again.\n")
                        break

                except FileNotFoundError:  # Touch config.txt if not present in installation folder
                    dec = input("File config.txt can be created. Do you wish to proceed? Y/N")
                    if dec == "Y" or dec == "y":  # Touch config.txt
                        conf = open(os.path.join(os.getcwd(), "config.txt"), "w")
                        conf.write(new)
                        conf.close()
                        print("File config.txt has been generated. Returning to launcher.")
                        exec(open("launcher.py").read())

                    elif dec == "N" or dec == "n": # Return to launcher.py
                        print("Decided not to create config.txt. Returning to Scoria launcher...")
                        print("=================================================================\n")
                        exec(open("launcher.py").read())

                    else:
                        print("Incorrect input! Try again.\n")
                        break

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
            print("Invalid port number. Please try again.\n")
        else:
            break

    while True:
        olim = int(input("Please provide the *LOWEST* port number you wish to scan: "))  # TypeError handling?
        if olim > 65536 or olim < 1 or olim > ulim:
            print("Invalid port number. Please try again.")
        else:
            break
    
    # print(f"Upper limit: {ulim}, Lower limit: {olim}")  # For debugging
    scanHost(ipaddr, olim, ulim)


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
# Implement checking for banners/services per port (banners are service-specific, not host-specific!!!)
# Integrate these checks into the config file (make parameter checks into their own function?)
# Implement port scanning for multiple non-continuous port numbers (i.e., 4, 1408, etc.) -- this is a secondary concern, as it is not crucial functionality
# Consider implementing portable script execution

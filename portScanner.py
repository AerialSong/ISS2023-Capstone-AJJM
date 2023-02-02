#!/usr/bin/bash

import socket
import sys
import subprocess
import re
import time
from datetime import datetime

# Code by Mackenzie Cleland, 2023

subprocess.call('clear', shell=True)    # Clears


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
                genflow = genflow + 1   # Facilitates breaking out of both loops
                break
            elif yesno == "N" or yesno == "n":  # Will trigger outer loop to restart
                print("Please enter parameters again.")
                break
            else:   # Will also trigger outer loop to restart
                print("Improper input entered. Please choose again.")
                break


def readConfig():   # Reads from config.txt and scans based on its parameters; remember error handling for empty file!
    # Put code here!
    pass


def scanHost():     # Establishes upper and lower limits on ports, then scans IP using this range.
    timea = datetime.now()

    while True:  # Retrieves IP address to be scanned
        ipaddr = input("Please provide IP address of server to be scanned: ")
        if not re.match(r'\d+(?:\.\d+){3}', ipaddr):  # Regex to match up IP syntax
            print("Invalid IP address. Please try again.")
        else:
            break

    while True:
        ulim = int(input("Please provide the highest port number you wish to scan: ")) + 1
        if ulim > 65536 or ulim < 1:
            print("Invalid port number. Please try again.")
            sys.exit()
        else:
            break

    while True:
        olim = int(input("Please provide the lowest port number you wish to scan: "))  # TypeError handling?
        if olim > 65536 or olim < 1 or olim > ulim:
            print("Invalid port number. Please try again.")
            sys.exit()
        else:
            break

    print("Starting port scanning operation...")    # Prompt
    time.sleep(3)
    print(f"Scanning ports {olim} - {ulim}...")
    try:
        for p in range(olim, ulim):
            csocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # This syntax may be Unix-exclusive (?)
            cconn = csocket.connect_ex((ipaddr, p))
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
    print(f"Completed scan of ports {olim} - {ulim} on server with IP address {ipaddr}")
    print(f"Total time elapsed: {total}")


def main():     # Main flow control for program
    while True:
        print("Which operation do you wish to carry out?")
        choice = int(input("1. Write to config.txt\n2. Read from config.txt and scan\n3. Custom scan\n"))
        if choice == 1:
            genConfig()
            break
        elif choice == 2:
            # readConfig()
            pass
            # break
        elif choice == 3:
            scanHost()
            break       # Breaks out of main loop
        else:
            print("Invalid choice selected. Please try again.")

# Add a "Do you wish to run another scan? Y/N" loop here? (Within the previous?)


main()


# TO DO:
# Implement config file generation
# Implement reading from config file
# Implement better error handling for scanning than just exiting, if possible

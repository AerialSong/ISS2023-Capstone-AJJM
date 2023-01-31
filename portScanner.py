#!/usr/bin/bash

import socket
import sys
import subprocess
import re
import time
from datetime import datetime

# Code by Mackenzie Cleland, 2023

subprocess.call('clear', shell=True)    # Clears terminal

while True:  # Retrieves IP address to be scanned
    ipaddr = input("Please provide IP address of server to be scanned: ")
    if not re.match(r'\d+(?:\.\d+){3}', ipaddr):  # Regex to match up IP syntax
        print("Invalid IP address. Please try again.")
    else:
        break

print("Starting port scanning operation...")    # Prompt
time.sleep(3)


def scanHost():     # Establishes upper and lower limits on ports, then scans IP using this range.
    timea = datetime.now()

    while True:
        ulim = int(input("Please provide the highest port number you wish to scan: ")) + 1
        if ulim > 65535 or ulim < 1:
            print("Invalid port number. Please try again.")
        else:
            break

    while True:
        olim = int(input("Please provide the lowest port number you wish to scan: "))  # TypeError handling?
        if olim > 65535 or olim < 1 or olim > ulim:
            print("Invalid port number. Please try again.")
            sys.exit()
        else:
            break

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
        print("Failed to resolve hostname. Exiting program.")
        sys.exit()
    except socket.error():
        print("Failed to connect to server. Exiting program.")
        sys.exit()

    timeb = datetime.now()
    total = timeb - timea
    print(f"Completed scan of ports {olim} - {ulim} on server with IP address {ipaddr}")
    print(f"Total time elapsed: {total}")


scanHost()

# TO DO:
# Implement config file generation
# Implement reading from config file
# Implement better error handling for scanning than just exiting, if possible

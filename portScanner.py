#!/usr/bin/bash

import socket
import sys
import subprocess
from datetime import datetime

# Code by Mackenzie Cleland, 2023

subprocess.call('clear', shell=True)    # Clears terminal screen
ipaddr = int(input("Please provide IP address of remote server to be scanned: "))  # Syntax handling?
print("Starting port scanning operation...")    # Prompt
# wait()


def scanHost():     # Reads host_config.txt and uses its information to scan the host system
    timea = datetime.now()

    limit = int(input("Please provide the highest port number you wish to scan: ")) + 1  # TypeError handling?
    while True:
        if limit > 65535 or limit < 1:
            print("Invalid port number. Please try again.")
            sys.exit()
        else:
            break

    try:
        for p in range(1, limit):
            csocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cconnect = csocket.connect_ex((ipaddr, p))
            if cconnect == 0:
                print(f"Port {p} is open!")
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
    print(f"Scan complete! Total time elapsed: {total}")


scanHost()

# TO DO:
# Implement error handling for IP address and port number upper limit
# Implement config file generation
# Implement reading from config file
# Implement better error handling for scanning than just exiting, if possible
# Implement lower limit for port scanning range


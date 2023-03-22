#!/usr/bin/bash

import sys
import importlib

# Code by Mackenzie Cleland, 2023


def printBanner():  # Prints the main banner for the program
    with open("banner.txt", "r") as f:
        print(f.read())
        f.close()


def launchFlow():  # Flow control for individual script execution
        while True:
            yesnt = input("Do you wish to run this service again? Y/N\n")
            if yesnt == "Y" or yesnt == "y":
                print("Running service again.\n")
                runScripts()
                print("")
            elif yesnt == "N" or yesnt == "n":
                print("Acknowledged. Exiting program.")
                sys.exit()
            else:
                print("Invalid input detected! Please try again.\n")


def runScripts():  # Flow control for main program functionality

    while True:
        print("Welcome to SCORIA! What would you like to do?")
        print("")
        choice = int(input("1. Scan ports\n2. Monitor traffic\n3. Detect intrusions on host\n4. Export logs to cloud\n5. Quit program\n"))

        if choice == 1:
            if ports not in sys.modules:
                import ports
            else:
                importlib.reload(ports)
            launchFlow()  # Not sure if should be indented
        elif choice == 2:
            if sniffer not in sys.modules:
                import sniffer
            else:
                importlib.reload(sniffer)
            if linput not in sys.modules:
                import linput
            else:
                importlib.reload(linput)
            launchFlow()
        elif choice == 3:
            if sigids not in sys.modules:
                import sigids
            else:
                importlib.reload(sigids)
            if netmon not in sys.modules:
                import netmon
            else:
                importlib.reload(netmon)
            launchFlow()
        elif choice == 4:
            print("Cloud functionality coming soon! :D")
            if s3nder not in sys.modules:
                import s3nder
            else:
                importlib.reload(s3nder)
            launchFlow()
        elif choice == 5:
            print("Acknowledged. Exiting program...")
            sys.exit()
        else:
            print("Invalid choice detected! Please try again.")
            print("")


printBanner()
runScripts()


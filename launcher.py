#!/usr/bin/bash

import sys

# Code by Mackenzie Cleland, 2023

# Implement bash syntax to launch Python3 first, then run the rest inside the Python shell, likely via venv module or similar environment.

runthis = ""  # Placeholder string for script execution arguments


def printBanner():  # Prints the main banner for the program
    with open("banner.txt", "r") as f:
        print(f.read())

# This code will likely expand to include calls for launching each of our scripts; it will thus be the main file called by the terminal.


def launchFlow(script):  # Flow control for individual script execution
        while True:
            yesnt = input("Do you wish to run this service again? Y/N\n")
            if yesnt == "Y" or yesnt == "y":
                print("")
                runScripts(script)
                print("")
                break
            elif yesnt == "N" or yesnt == "n":
                break
            else:
                print("Invalid input detected! Please try again.\n")


def runScripts(runthis):  # Flow control for main program functionality

    while True:
        print("Welcome to SCORIA! What would you like to do?")
        print("")
        choice = int(input("1. Scan ports\n2. Monitor traffic\n3. Export logs to cloud\n4. Quit program\n"))

        if choice == 1:
            runthis = "ports.py"
            # run runthis
            launchFlow(runthis)
            break
        elif choice == 2:
            runthis = "netMonitor.py"
            # run runthis
            launchFlow(runthis)
            break
        elif choice == 3:
            # runthis = "cloudscriptnamehere.py"
            # run cloud script
            launchFlow(runthis)
            break
        elif choice == 4:
            print("Acknowledged. Exiting program...")
            sys.exit()
        else:
            print("Invalid choice detected! Please try again.")
            print("")


printBanner()
runScripts(runthis)


# TO DO:
# Implement proper string parsing for script execution in runScripts()


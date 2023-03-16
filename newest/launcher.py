#!/usr/bin/bash

import sys

# Code by Mackenzie Cleland, 2023

# Implement bash syntax to launch Python3 first, then run the rest inside the Python shell, likely via venv module or similar environment.


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
        choice = int(input("1. Scan ports\n2. Monitor traffic\n3. Export logs to cloud\n4. Quit program\n"))

        if choice == 1:
            import ports  # Can't find functions in script!
            launchFlow()
        elif choice == 2:
            # import scoriaoutputnetmonitor
            launchFlow()
        elif choice == 3:
            print("Cloud functionality coming soon! :D")
            launchFlow()
        elif choice == 4:
            print("Acknowledged. Exiting program...")
            sys.exit()
        else:
            print("Invalid choice detected! Please try again.")
            print("")


printBanner()
runScripts()


# TO DO:
# Implement import statements for our other scripts!

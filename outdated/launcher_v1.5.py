#!/usr/bin/python3

import sys

import ports
import netIDS
# import sniffer

# Code by Mackenzie Cleland, 2023


def printBanner():  # Prints the main banner for the program
    with open("banner.txt", "r") as f:
        print(f.read())
        f.close()


# def launchFlow():  # Flow control for individual script execution
#         while True:
#             yesnt = input("Do you wish to run this service again? Y/N\n")
#             if yesnt == "Y" or yesnt == "y":
#                 print("Running service again.\n")
#                 runScripts()
#                 print("")
#             elif yesnt == "N" or yesnt == "n":
#                 print("Acknowledged. Exiting program.")
#                 sys.exit()
#             else:
#                 print("Invalid input detected! Please try again.\n")


def runScripts():  # Flow control for main program functionality

    # while True:
        print("Welcome to SCORIA! What would you like to do?")
        print("")
        choice = int(input("1. Scan ports\n2. Monitor traffic (Currently only works on Linux systems!!!)\n3. Detect intrusions on host\n4. Quit program\n"))

        if choice == 1:
            ports.main()
        # elif choice == 2:
        #     sniffer.main()
        #     launchFlow()
        elif choice == 3:
            netIDS.main()
            print("\n")
        #     launchFlow()
        elif choice == 4:
            print("Acknowledged. Exiting program...")
            sys.exit()
        else:
            print("Invalid choice detected! Please try again.")
            print("")

        sys.exit()


printBanner()
runScripts()

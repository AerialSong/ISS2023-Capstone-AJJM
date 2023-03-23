#!/usr/bin/bash

import sys

# Code by Mackenzie Cleland, 2023

# Implement bash syntax to launch Python3 first, then run the rest inside the Python shell, likely via venv module or similar environment.


def printBanner():  # Prints the main banner for the program
    with open("banner.txt", "r") as f:
        print(f.read())
        f.close()


def runScripts():  # Flow control for main program functionality
   print("Welcome to SCORIA! What would you like to do?")
   print("")
   choice = int(input("1. Scan ports\n2. Monitor traffic\n3. Export logs to cloud\n4. Quit program\n"))

   if choice == 1:
      import ports
   
   elif choice == 2:
      import sniffer

   elif choice == 3:
      import netids

   elif choice == 4:
      print("Acknowledged. Exiting program...")
      sys.exit()
      
   else:
      print("Invalid choice detected! Please try again.")
      print("")


printBanner()
runScripts()

#!/usr/bin/bash

# Code by Mackenzie Cleland, 2023

# Implement bash syntax to launch Python3 first, then run the rest inside the Python shell, likely via venv module or similar environment.


def printBanner():  # Prints the main banner for the program
    with open("banner.txt", "r") as f:
        print(f.read())

# This code will likely expand to include calls for launching each of our scripts; it will thus be the main file called by the terminal.


def runScripts():  # Flow control for main program functionality
    while True:
        print("Welcome to SCORIA! What would you like to do?")
        print("")
        choice = int(input("1. Scan ports\n2. Monitor traffic\n3. Export logs to cloud"))

        if choice == 1:
            # run portScanner.py
            break
        elif choice == 2:
            # run netMonitor.py
            break
        elif choice == 3:
            # run cloud script
            break
        else:
            print("Invalid choice detected! Please try again.")
            print("")


printBanner()

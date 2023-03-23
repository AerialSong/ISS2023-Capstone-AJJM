#!/usr/bin/python3
import argparse
import json

def main():
    # parser object
    parser = argparse.ArgumentParser(description="A lightweight command-line based Network Traffic Analyzer")

    parser.add_argument("-dest", "--destination", type=str, nargs=1, metavar="destination_ip", default=None, help="Specify your desired Destination IP Address for filtration; Syntax = 111.222.333.444")
    parser.add_argument("-s", "--source", type=str, nargs=1, metavar="source_ip", default=None, help="Specify your desired source IP Address for filtration; Syntax = 111.222.333.444")
    parser.add_argument("-pr", "--protocol", type=str, nargs=1, metavar="protocol_name", default=None, help="Specify your desired protocol name for filtration; TCP or UDP")
    parser.add_argument("-sp", "--srcport", type=str, nargs=1, metavar="src_port_num", default=None, help="Specify your desired Source Port number for filtration, from 1-65535")
    parser.add_argument("-dp", "--destport", type=str, nargs=1, metavar="dest_port_num", default=None, help="Specify your desired Destination Port number for filtration, from 1-65535")
    parser.add_argument("-sm" , "--srcmac", type=str, nargs=1, metavar="src_mac", default=None, help="Specify your desired Source Mac address for filtrationCase Sensitive; Syntax = 0A:0A:0A:0A:0A:0A")
    parser.add_argument("-dm" , "--destmac", type=str, nargs=1, metavar="dest_mac", default=None, help="Specify your desired Destination Mac address for filtrationCase Sensitive; Syntax = 0A:0A:0A:0A:0A:0A")
    parser.add_argument("-d", "--date", type=str, nargs=1, metavar="date", default=None, help="Specify your desired date of packet creation for filtration; Syntax = MMdd")
    parser.add_argument("-t", "--time", type=str, nargs=1, metavar="time", default=None, help="Specify your desired time of packet creation for filtration; Syntax = HHmm")
    parser.add_argument("-c", "--clear", action="store_true", help="Clear all already entered arguments")
    parser.add_argument("-sl", "--sleep", type=float, nargs=1, metavar="sleep_sec", default=None, help="Specify how many seconds you would like the output to sleep upon printing a packet; for an easier to follow output.")

    args = parser.parse_args()

    # Creates txt file, 
    with open("arg.txt", "w") as f:
        json.dump(args.__dict__, f, indent=2)

if __name__ == "__main__":
    main()

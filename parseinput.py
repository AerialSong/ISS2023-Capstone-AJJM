import argparse
import json

'''
copy paste the parser object and argument info
upon command entry, send command to txt file
parseoutput reads txt file and takes command
variables change
voila
'''

def main():
    # parser object
    parser = argparse.ArgumentParser(description="A lightweight command-line based Network Traffic Analyzer")

    parser.add_argument("-des", "--destination", "-dest", type=str, nargs=1, metavar="destination_ip", default=None, help="Destination IP Address")
    parser.add_argument("-s", "--source", type=str, nargs=1, metavar="source_ip", default=None, help="Source IP Address")
    parser.add_argument("-pr", "--protocol", type=str, nargs=1, metavar="protocol_name", default=None, help="Type of protocol")
    parser.add_argument("-p", "--port", type=str, nargs=1, metavar="port_num", default=None, help="Port Number")
    parser.add_argument("-d", "--date", type=int, nargs=1, metavar="date", default=None, help="Date packet was made; Syntax = MMdd")
    parser.add_argument("-t", "--time", type=str, nargs=1, metavar="time", default=None, help="Time packet was made; Syntax = HHmm")

    args = parser.parse_args()

    # Creates txt file, 
    with open("arg.txt", "w") as f:
        json.dump(args.__dict__, f, indent=2)

if __name__ == "__main__":
    main()
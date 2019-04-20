#!/usr/bin/env python3

# Standard library imports
import argparse
import subprocess

def arg_handler():
    parser = argparse.ArgumentParser(description='DPI on packets', add_help=False)
    parser.add_argument("-h", "--help", help="Help message", action="store_true")

    group = parser.add_argument_group(title='required arguments')
    group.add_argument("-f", "--flowlist", metavar="NAME", help="Specify type of flows to be searched", nargs='+', type=str)
    group.add_argument("-d", "--duration", help="Capture duration in seconds", type=int)
    group.add_argument("-t", "--period", help="Capture period in seconds (polling frequency)", type=int)
    
    args = parser.parse_args()
    # Testing
    if args.help:
        parser.print_help()
    if args.flowlist:
    	print(args.flowlist)
    if args.duration:
    	print(args.duration)
    if args.period:
    	print(args.period)

def main():
    arg_handler()


if __name__ == "__main__":
    main()
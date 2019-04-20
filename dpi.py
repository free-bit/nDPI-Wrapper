#!/usr/bin/env python3

# Standard library imports
import argparse
import subprocess
import threading as th

# Custom format for arg Help print
class CustomFormatter(argparse.HelpFormatter):
    def __init__(self,
                 prog,
                 indent_increment=2,
                 max_help_position=100, # Modified
                 width=None):
        super().__init__(prog, indent_increment, max_help_position, width)

    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            if action.nargs == 0:
                parts.extend(action.option_strings)

            else:
                default = action.dest.upper()
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append('%s' % option_string)
                parts[-1] += ' %s' % args_string
            return ', '.join(parts)

# Handles cmd args
def arg_handler():
    parser = argparse.ArgumentParser(description='DPI on packets', 
                                     formatter_class=CustomFormatter, 
                                     add_help=False)
    parser.add_argument("-h", "--help", help="Help message", action="store_true")

    group = parser.add_argument_group(title='required arguments')

    group.add_argument("-i", "--interfaces", help="Network interfaces", 
                       metavar=("I0", "I1"), nargs='+', type=str)

    group.add_argument("-f", "--flows",  help="Flows to search", 
                       metavar=("F1", "F2"), nargs='+', type=str)

    group.add_argument("-d", "--duration", help="Capture duration in seconds", 
                       metavar="TIME", type=int)

    group.add_argument("-t", "--period", help="Capture period in seconds", 
                       metavar="TIME", type=int)
    
    args = parser.parse_args()
    # Testing
    if args.help:
        parser.print_help()
    if args.interfaces:
        print(args.interfaces)
    if args.flows:
        print(args.flows)
    if args.duration:
        print(args.duration)
    if args.period:
        print(args.period)

def main():
    arg_handler()

    # 
    # print(out.decode())


if __name__ == "__main__":
    main()
#!/usr/bin/env python3

# Standard library imports
import argparse
import ipaddress as ip
import os
import re
import subprocess
import threading as th
from time import sleep


# Regex for IPv4
rxp_ipv4 = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}' +\
           r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
# Regex for IPv6
rxp_ipv6 = r'(?:(?:(?:[0-9A-Fa-f]{1,4}:){6}' +\
           r'|::(?:[0-9A-Fa-f]{1,4}:){5}' +\
           r'|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}' +\
           r'|(?:(?:[0-9A-Fa-f]{1,4}:){0,1}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}' +\
           r'|(?:(?:[0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}' +\
           r'|(?:(?:[0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:' +\
           r'|(?:(?:[0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})?::' +\
           r')(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}' +\
           r'|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}' +\
           r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))' +\
           r'|(?:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}' +\
           r'|(?:(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})?::)'
# Reference: http://www.jmrware.com/articles/2009/uri_regexp/URI_regex.html

# Regex covering both IPv4 and IPv6 
rxp_ip = r"({}|{})".format(rxp_ipv4, rxp_ipv6)
# Regex for protocol field of nDPI
rxp_proto = r'\[proto: \d+(?:^$|(?:\.\d+)*)/(.*?)\]'
# Full regex
regex = rxp_ip + r'.*?' + rxp_ip + r'.*?' + rxp_proto
# Compile for efficiency
regex = re.compile(regex)


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
    parser.add_argument("--filter", help="Filter private IPs", default=False, action="store_true")

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
    
    # Checking args
    if args.help:
        parser.print_help()
    
    if args.interfaces and args.flows and args.duration and args.period:
        return args
    
    return None

# Runs ndpiReader as subproc for a certain duration periodically 
def dpi_routine(interfaces, duration, period, captures, condition):
    interfaces = " ".join(interfaces)
    command = "ndpiReader -v 1 -i {} -s {}".format(interfaces, duration)

    while True: 
        out = subprocess.run([command], shell=True, capture_output=True).stdout
        captures.append(out.decode())
        with condition:
            condition.notify()
        sleep(period)

def parse_capture():
    pass

def switch_routine(flows, filterIP, captures, condition):
    while True:
        with condition:
            condition.wait()
        capture = captures.pop()
        ips = parse_capture(capture, flows, filterIP)

def regex_test():
    with open('outputv1.txt', 'r') as file:
        text = file.read()
        groups = re.findall(regex, text)
        blockedIPs = []
        flows = ["Github"]
        for group in groups:
            print(group)
            if (flows[0] in group[2]):
                ip1 = ip.IPv4Address(group[0])
                ip2 = ip.IPv4Address(group[1])
                if ip1.is_global:
                    blockedIPs.append(ip1)
                if ip2.is_global:
                    blockedIPs.append(ip2)
        # print(blockedIPs)

def main():
    regex_test() # tmp
    # uid = os.geteuid()
    # if (uid == 0):
    #     args = arg_handler()
    #     if args:
    #         captures = []
    #         condition = th.Condition()
    #         dpi_thread = th.Thread(target=dpi_routine, 
    #                                args=(args.interfaces, args.duration, args.period, 
    #                                      captures, condition))
    #         swi_thread = th.Thread(target=switch_routine, 
    #                                args=(args.flows, args.filter, captures, condition))
    #         dpi_thread.start()
    #         swi_thread.start()
    #         swi_thread.join()
    #         dpi_thread.join()
    # else:
    #     print("Run the script as root")


if __name__ == "__main__":
    main()
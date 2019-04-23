#!/usr/bin/env python3

# Standard library imports
import argparse
import os
import re
import subprocess
import threading as th
from time import sleep

import grpc
# Don't forget to add the directory where p4runtime_lib resides to PYTHONPATH.
# It is at $HOME/tutorials/utils in the standart tutorial VM installation.
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

# Lookup table generated from ndpiReader docs
proto_lookup = {
    'unknown':  0,
    'ftp_control':  1,
    'pop3':  2,
    'smtp':  3,
    'imap':  4,
    'dns':  5,
    'ipp':  6,
    'http':  7,
    'mdns':  8,
    'ntp':  9,
    'netbios': 10,
    'nfs': 11,
    'ssdp': 12,
    'bgp': 13,
    'snmp': 14,
    'xdmcp': 15,
    'smbv1': 16,
    'syslog': 17,
    'dhcp': 18,
    'postgresql': 19,
    'mysql': 20,
    'hotmail': 21,
    'direct_download_link': 22,
    'pops': 23,
    'applejuice': 24,
    'directconnect': 25,
    'ntop': 26,
    'coap': 27,
    'vmware': 28,
    'smtps': 29,
    'facebookzero': 30,
    'ubntac2': 31,
    'kontiki': 32,
    'openft': 33,
    'fasttrack': 34,
    'gnutella': 35,
    'edonkey': 36,
    'bittorrent': 37,
    'skypecall': 38,
    'signal': 39,
    'memcached': 40,
    'smbv23': 41,
    'mining': 42,
    'nestlogsink': 43,
    'modbus': 44,
    # 'free': 45,
    # 'free': 46,
    'xbox': 47,
    'qq': 48,
    # 'free_49': 49,
    'rtsp': 50,
    'imaps': 51,
    'icecast': 52,
    'pplive': 53,
    'ppstream': 54,
    'zattoo': 55,
    'shoutcast': 56,
    'sopcast': 57,
    'tvants': 58,
    'tvuplayer': 59,
    'http_download': 60,
    'qqlive': 61,
    'thunder': 62,
    'soulseek': 63,
    'ssl_no_cert': 64,
    'irc': 65,
    'ayiya': 66,
    'unencrypted_jabber': 67,
    'msn': 68,
    'oscar': 69,
    'yahoo': 70,
    'battlefield': 71,
    'googleplus': 72,
    'vrrp': 73,
    'steam': 74,
    'halflife2': 75,
    'worldofwarcraft': 76,
    'telnet': 77,
    'stun': 78,
    'ipsec': 79,
    'gre': 80,
    'icmp': 81,
    'igmp': 82,
    'egp': 83,
    'sctp': 84,
    'ospf': 85,
    'ip_in_ip': 86,
    'rtp': 87,
    'rdp': 88,
    'vnc': 89,
    'pcanywhere': 90,
    'ssl': 91,
    'ssh': 92,
    'usenet': 93,
    'mgcp': 94,
    'iax': 95,
    'tftp': 96,
    'afp': 97,
    'stealthnet': 98,
    'aimini': 99,
    'sip':100,
    'truphone':101,
    'icmpv6':102,
    'dhcpv6':103,
    'armagetron':104,
    'crossfire':105,
    'dofus':106,
    'fiesta':107,
    'florensia':108,
    'guildwars':109,
    'http_activesync':110,
    'kerberos':111,
    'ldap':112,
    'maplestory':113,
    'mssql-tds':114,
    'pptp':115,
    'warcraft3':116,
    'worldofkungfu':117,
    'slack':118,
    'facebook':119,
    'twitter':120,
    'dropbox':121,
    'gmail':122,
    'googlemaps':123,
    'youtube':124,
    'skype':125,
    'google':126,
    'dce_rpc':127,
    'netflow':128,
    'sflow':129,
    'http_connect':130,
    'http_proxy':131,
    'citrix':132,
    'netflix':133,
    'lastfm':134,
    'waze':135,
    'youtubeupload':136,
    'genericprotocol':137,
    'checkmk':138,
    'ajp':139,
    'apple':140,
    'webex':141,
    'whatsapp':142,
    'appleicloud':143,
    'viber':144,
    'appleitunes':145,
    'radius':146,
    'windowsupdate':147,
    'teamviewer':148,
    'tuenti':149,
    'lotusnotes':150,
    'sap':151,
    'gtp':152,
    'upnp':153,
    'llmnr':154,
    'remotescan':155,
    'spotify':156,
    'messenger':157,
    'h323':158,
    'openvpn':159,
    'noe':160,
    'ciscovpn':161,
    'teamspeak':162,
    'tor':163,
    'ciscoskinny':164,
    'rtcp':165,
    'rsync':166,
    'oracle':167,
    'corba':168,
    'ubuntuone':169,
    'whois-das':170,
    'collectd':171,
    'socks':172,
    'nintendo':173,
    'rtmp':174,
    'ftp_data':175,
    'wikipedia':176,
    'zeromq':177,
    'amazon':178,
    'ebay':179,
    'cnn':180,
    'megaco':181,
    'redis':182,
    'pando_media_booster':183,
    'vhua':184,
    'telegram':185,
    'vevo':186,
    'pandora':187,
    'quic':188,
    'whatsappvoice':189,
    'eaq':190,
    'ookla':191,
    'amqp':192,
    'kakaotalk':193,
    'kakaotalk_voice':194,
    'twitch':195,
    # 'free':196,
    'wechat':197,
    'mpeg_ts':198,
    'snapchat':199,
    'sina(weibo)':200,
    'googlehangout':201,
    'iflix':202,
    'github':203,
    'bjnp':204,
    # 'free':205,
    # 'ppstream':206,
    'smpp':207,
    'dnscrypt':208,
    'tinc':209,
    'deezer':210,
    'instagram':211,
    'microsoft':212,
    'starcraft':213,
    'teredo':214,
    'hotspotshield':215,
    'hep':216,
    'googledrive':217,
    'ocs':218,
    'office365':219,
    'cloudflare':220,
    'ms_onedrive':221,
    'mqtt':222,
    'rx':223,
    'applestore':224,
    'opendns':225,
    'git':226,
    'drda':227,
    'playstore':228,
    'someip':229,
    'fix':230,
    'playstation':231,
    'pastebin':232,
    'linkedin':233,
    'soundcloud':234,
    'csgo':235,
    'lisp':236,
    'diameter':237,
    'applepush':238,
    'googleservices':239,
    'amazonvideo':240,
    'googledocs':241,
    'whatsappfiles':242,
}

# Regex for IPv4
RXP_IPV4 = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}' +\
           r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
# Regex for IPv6
RXP_IPV6 = r'(?:(?:(?:[0-9A-Fa-f]{1,4}:){6}' +\
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
RXP_IP = r"({}|{})".format(RXP_IPV4, RXP_IPV6)
# Regex for protocol field of nDPI
RXP_PROTO = r'(?:\[proto: (?:\d+\.)*?(?:{})?/(?:.*?)\])'
# Full regex will be generated after flows are mapped to IDs
FULL_REGEX = None

# Custom format for argparse help print
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

def print_known_flows():
    print("Flows known to nDPI:")
    print("--------------------")
    for (name, id) in proto_lookup.items():
        print((str(id) + ":\t"), name)

# Handles cmd args
def arg_handler():
    global RXP_IP, RXP_PROTO, FULL_REGEX
    parser = argparse.ArgumentParser(description='DPI on packets', 
                                     formatter_class=CustomFormatter, 
                                     add_help=False)
    parser.add_argument("-h", "--help", help="Help message", action="store_true")
    parser.add_argument("-p", "--printflows", help="Print flows known to nDPI", default=False, action="store_true")
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=True)
    group = parser.add_argument_group(title='required arguments')
    group.add_argument("-i", "--interfaces", help="Network interfaces", 
                       metavar=("I0", "I1"), nargs='+', type=str)
    group.add_argument("-f", "--flows",  help="Flow names (known to nDPI) to search", 
                       metavar=("F1", "F2"), nargs='+', type=str)
    group.add_argument("-d", "--duration", help="Capture duration in seconds", 
                       metavar="TIME", type=int)
    group.add_argument("-t", "--period", help="Capture period in seconds", 
                       metavar="TIME", type=int)
    args = parser.parse_args()
    
    # Checking args
    if args.help:
        parser.print_help()
    if args.printflows:
        print_known_flows()
    if args.interfaces and args.flows and args.duration and args.period:
        flow_names = args.flows
        args.flows = []

        # Convert flow names to nDPI IDs by using the lookup table
        for flow in flow_names:
            try:
                args.flows.append(proto_lookup[flow.lower()])
            except Exception as e:
                print("Unknown protocol name:", e, "ignoring...")

        # If at least one flow is found in the lookup proceed with
        # generating the regex which capture IP addresses for specified flows
        if args.flows:
            # Regex for flowIDs
            flow_exp = "{}"
            for _ in range(len(args.flows)-1):
                flow_exp += "|{}"
            flow_exp = flow_exp.format(*args.flows)
            
            # Regex for the protocol part of nDPI (in the global scope)
            RXP_PROTO = RXP_PROTO.format(flow_exp)
            
            # Full regex (in the global scope)
            FULL_REGEX = RXP_IP + r'.*?' + RXP_IP + r'.*?' + RXP_PROTO
            FULL_REGEX = re.compile(FULL_REGEX)

            return args
    
    return None

# Runs ndpiReader as subproc for a certain duration periodically 
def dpi_routine(interfaces, duration, period, captures, condition): 
    interfaces = " ".join(interfaces)
    command = "ndpiReader -v 1 -i {} -s {}".format(interfaces, duration)
    while True: 
        out = subprocess.run([command], shell=True, capture_output=True).stdout
        captures.append(out.decode())
        # Notify switch_routine when the capture output is ready
        with condition:
            condition.notify()
        sleep(period)

# Parses the capture output and extracts ip addresses
def parse_capture(capture, flows):
    global FULL_REGEX
    # Keep only one instance of each (srcIP, dstIP) pair in the set 
    blockedIPs = set()
    groups = re.findall(FULL_REGEX, capture)
    for group in groups: # group -> (srcIP, dstIP)
        blockedIPs.add((group[0], group[1]))
    return list(blockedIPs)

# Obtain IP addresses associated with the specified flows
def switch_routine(flows, captures, condition, switch_connection, p4info_helper):
    # Continuously wait and process capture outputs
    while True:
        with condition:
            condition.wait()
        capture = captures.pop()
        ips = parse_capture(capture, flows)
        print(ips)

        for pair in ips:
            table_entry = p4info_helper.buildTableEntry(
                table_name="ingress.blocklist",
                match_fields={
                    "hdr.ipv4.srcAddr": pair[0],
                    "hdr.ipv4.dstAddr": pair[1]
                },
                action_name="ingress.my_drop",
                )
            switch_connection.WriteTableEntry(table_entry)

'''
usage: dpi.py [-h] [-p] [-i I0 [I1 ...]] [-f F1 [F2 ...]] [-d TIME]
              [-t TIME]

DPI on packets

optional arguments:
  -h, --help                    Help message
  -p, --printflows              Print flows known to nDPI

required arguments:
  -i, --interfaces I0 [I1 ...]  Network interfaces
  -f, --flows F1 [F2 ...]       Flow names (known to nDPI) to search
  -d, --duration TIME           Capture duration in seconds
  -t, --period TIME             Capture period in seconds
'''
def main():
    # Check for root privileges
    uid = os.geteuid()
    if (uid != 0):
        print("Run the script as root")
        return

    # Check for args
    args = arg_handler()
    if not args:
        return

    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    # Initiate switch connection.
    # This code is adapted from p4lang/tutorials (https://github.com/p4lang/tutorials).
    try:
        # Create a switch connection object for the switch;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt file.
        switch_connection = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1', # XXX: What does this name correspond to?
            address='192.168.9.99:50051', # TODO: Parametrize the IP/port
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        switch_connection.MasterArbitrationUpdate()
    except grpc.RpcError as e:
        printGrpcError(e)
        return

    captures = []
    condition = th.Condition()
    dpi_thread = th.Thread(target=dpi_routine,
                           args=(args.interfaces, args.duration, args.period,
                                 captures, condition))
    swi_thread = th.Thread(target=switch_routine,
                           args=(args.flows, captures, condition,
                                 switch_connection, p4info_helper))
    dpi_thread.start()
    swi_thread.start()
    swi_thread.join()
    dpi_thread.join()

if __name__ == "__main__":
    main()

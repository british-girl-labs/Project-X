import scapy.all as scapy
import argparse
import pyfiglet
import requests
from shodan import Shodan
import pprint
import sys
from mac_vendor_lookup import MacLookup

ascii_banner = pyfiglet.figlet_format("Stark Net Scan")
print(ascii_banner)

def get_ip():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip", help="Target IP / IP Range --> [0.0.0.0/24]")
    return parser.parse_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    transmit = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_transmit = transmit / arp_request
    pickup = scapy.srp(arp_request_transmit, timeout=1, verbose=False)[0]

    mark_roster = []
    for unit in pickup:
        mark_dict = {"ip": unit[1].psrc, "mac": unit[1].hwsrc}
        mark_roster.append(mark_dict)
    return mark_roster


def print_roster(roster_list):
    print("IP\t\t\tMAC ADDRESS\t\t\tMAC VENDOR  \n_____________________________________________________________________________")
    for mark in roster_list:
        mac_ven_look = (MacLookup().lookup(mark["mac"]))
        print(mark["ip"] + "\t\t" + mark["mac"] + "\t\t" + mac_ven_look)
        



options = get_ip()
scan_roster = scan(options.ip)
print_roster(scan_roster)
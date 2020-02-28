# Name          :   InfoHunter
# Author        :   No_P33k
# Last edited   :   February 2020
# Purpose       :   This script is meant to give users the ability to enter a single
#               :   IP address or enter the name of an input file with a long list of IP
#               :   addresses and get ARIN details back.

import argparse
import time
from ipwhois import IPWhois
import ipwhois


def parse_arguments():
    parser = argparse.ArgumentParser(description="Run security check against single IP addresses or list of IPs")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--single", action="store_true", help="Check single IP")
    group.add_argument("-f", "--file", action="store_true", help="Check list of IPs")
    parser.add_argument("UserInput", type=str, nargs="?", help="Enter single IP or Filename")
    args = parser.parse_args()

    if args.UserInput:
        if args.single:
            print("\nChecking security details for single IP: {}".format(args.UserInput))
            check_ip(args.UserInput, False)
        elif args.file:
            print("\nChecking security details for all IPs in file {}".format(args.UserInput))
            file_open(str(args.UserInput))
        else:
            print("Improper usage. Type -h or --help for details.")
    else:
        print("Improper usage. Type -h or --help for details.")


def file_open(infile):
    try:
        f = open(infile, 'r')
        for line in f:
            time.sleep(1)
            print("\nGetting whois details on: {}".format(line))
            check_ip(line.strip(), True)
        f.close()
    except IOError:
        print("No such file. Please check the file name and try again.")


def check_ip(ip, single):
    try:
        obj = IPWhois(ip)
        try:
            res = (obj.lookup_rdap())
            print(res)
            asn_info = "ASN: " + res['asn'] + '\n' + "CIDR: " + res['asn_cidr'] + '\n'
            country_info = "Country: " + res['asn_country_code'] + "\n"
            ipdetails = asn_info + country_info + "\n"
            print(ipdetails)
            if single:
                write_to_file(ipdetails)
        except ipwhois.exceptions.ASNRegistryError:
            errorstring = ("No data for: {}".format(ip) + "\n\n")
            print(errorstring)
            write_to_file(errorstring)
    except ValueError:
        print("Please enter a valid IP")


def write_to_file(details):
    with open("Outfile.txt", "a+") as outfile:
        outfile.write(details)
        outfile.close()


if __name__ == '__main__': parse_arguments()

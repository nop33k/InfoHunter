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

    # Create initial parser and arguments
    parser = argparse.ArgumentParser(prog="InfoHunter",
                                     description="Run security check against single IP addresses or list of IPs")
    parser.add_argument("-s", "--single", action="store_true", help="Check single IP")
    parser.add_argument("-f", "--file", action="store_true", help="Check list of IPs")
    parser.add_argument("-v", "--virustotal", action="store_true", help="Add Virus Total Results")
    parser.add_argument("UserInput", type=str, nargs="?", help="Enter single IP or Filename")
    args = parser.parse_args()
    use_arguments(args)


def use_arguments(args):

    # take action on the arguments based on selection
    # action can only be taken if positional argument exists
    if args.UserInput:

        # take action only if optional argument is selected, else return error.
        # start with single IP check
        if args.single:
            if not args.virustotal:
                # run ARIN check on Single IP only
                print("\nChecking security details for single IP: {}".format(args.UserInput))
                check_ip(args.UserInput, False)

        # take action virustotal
        if args.virustotal:

            # check if this is single IP check
            if args.single:
                print("Checking security details, including VirusTotal for single IP: {}".format(args.UserInput))
                # change this to do additional checks
                # Insert VT related function call here

            # check if this is a file of IPs
            elif args.file:
                print("Checking security details, including VirusTotal for all IPs in file: {}".format(args.UserInput))
                # change this to do additional checks
                # Insert VT related function call here.

            # Notify user that -s or -f flags need to be chosen
            else:
                print("Must choose optional argument -s or -f for single IP or file with list of IPs.")

        # take action if file of IP addresses without virustotal requirement
        if args.file:
            print("\nChecking security details for all IPs in file {}".format(args.UserInput))
            file_open(str(args.UserInput))

        # handle error if no flag is selected
        elif not args.single:
            if not args.file:
                if not args.virustotal:
                    print("Improper usage. Type -h or --help for details.")

    # handle error is no positional argument is entered
    else:
        print("Improper usage. Type -h or --help for details.")


def file_open(infile):

    # open file of IPs with try statement to catch file error
    try:
        f = open(infile, 'r')
        for line in f:
            time.sleep(1)
            print("\nGetting whois details on: {}".format(line))

            # check IP details and write to file via True argument
            check_ip(line.strip(), True)
        f.close()

    # notify user that file does not exist
    except IOError:
        print("No such file. Please check the file name and try again.\n")


def check_ip(ip, multiple):

    # get Arin details for IP and print results to screen and write to file if multiple IPs
    # catch whois error through try statement
    try:
        obj = IPWhois(ip)

        # Get details and catch error if ASN Registry error
        try:
            res = (obj.lookup_rdap())
            asn_info = "ASN: " + res['asn'] + '\n' + "CIDR: " + res['asn_cidr'] + '\n'
            country_info = "Country: " + res['asn_country_code'] + "\n"
            ipdetails = asn_info + country_info + "\n"
            print(ipdetails)

            # write to file if single option is not chosen
            if multiple:
                write_to_file(ipdetails)

        # handle errors
        except ipwhois.exceptions.ASNRegistryError:
            errorstring = ("No data for: {}".format(ip) + "\n\n")
            print(errorstring)
            write_to_file(errorstring)

    # handle invalid IP address entries
    except ValueError:
        print("Please enter a valid IP address")


def write_to_file(details):

    # write to default file name
    with open("Outfile.txt", "a+") as outfile:
        outfile.write(details)
        outfile.close()


# start script
if __name__ == '__main__': parse_arguments()

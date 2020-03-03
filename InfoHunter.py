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
import requests

# set global variable for output file (if needed). This keeps it out of any for loops.
timestr = time.strftime("%Y%m%d-%H%M%S")
outputfile = timestr + "-output.txt"


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

    # Take action on the arguments based on selection
    # Action can only be taken if positional argument exists
    # This is is either a single IP or a listing of IPs
    if args.UserInput:

        # Take action only if optional argument is selected, else return error.
        # Start with single IP check
        if args.single:
            if not args.virustotal:
                # run ARIN check on Single IP only
                print("\nChecking security details for single IP: {}".format(args.UserInput))
                check_ip(args.UserInput, False)

        # Take action if Virustotal option is selected
        if args.virustotal:

            # Check if this is single IP check for Virustotal Check
            if args.single:
                print("Checking security details, including VirusTotal for single IP: {}".format(args.UserInput))

                # Run the Virustotal check against a single IP
                check_virustotal(args.UserInput, False)

            # Check if this is a file of IPs
            elif args.file:
                print("Checking security details, including VirusTotal for all IPs in file: {}".format(args.UserInput))

                # Run the Virustotal check against file of IPs
                file_open(str(args.UserInput), True)

            # Notify user that -s or -f flags need to be chosen
            else:
                print("Must choose optional argument -s or -f for single IP or file with list of IPs.")

        # Take action if file of IP addresses without virustotal requirement
        if args.file:
            if not args.virustotal:
                print("\nChecking security details for all IPs in file {}".format(args.UserInput))
                file_open(str(args.UserInput), False)

        # Handle error if no flag is selected
        elif not args.single:
            if not args.file:
                if not args.virustotal:
                    print("Improper usage. Type -h or --help for details.")

    # handle error is no positional argument is entered
    else:
        print("Improper usage. Type -h or --help for details.")


def file_open(infile, virustotal):

    # Open file of IPs with try statement to catch file error
    try:
        f = open(infile, 'r')

        # If file opens properly, iterate over each line
        for line in f:
            if virustotal:
                print("\nVirustotal option selected\n")
                write_to_file("\n\nVirustotal details for: {}".format(line))

                # Send IP address to Virustotal function for check with True set for multiple IP checks
                check_virustotal(line.strip(), True)

                # Sleep for 15 to limit Virustotal checks to 4 per minute (limit on FREE account)
                time.sleep(15)

            # If this is not a Virustotal check, just get ARIN details only
            else:
                print("\nGetting whois details on: {}".format(line))

                # Check IP details and write to file via True argument
                check_ip(line.strip(), True)

        # Proper file management
        f.close()

    # Notify user that file does not exist
    except IOError:
        print("No such file. Please check the file name and try again.\n")


def check_ip(ip, multiple):

    # Get Arin details for IP and print results to screen and write to file if multiple IPs
    # Catch whois error through try statement
    try:
        obj = IPWhois(ip)

        # Get details and catch error if ASN Registry error
        try:
            # See if we can get ARIN details
            res = (obj.lookup_rdap())

            # Define ASN & Country strings and combine
            asn_info = "ASN: " + res['asn'] + '\n' + "CIDR: " + res['asn_cidr']\
                       + '\n' + "ASN Date: " + res["asn_date"] + "\n"
            country_info = "Country: " + res['asn_country_code'] + "\n"
            ipdetails = asn_info + country_info + "\n"
            print(ipdetails)

            # Write to file if this is checking multiple IPs
            if multiple:
                write_to_file(ipdetails)

        # Handle errors
        except ipwhois.exceptions.ASNRegistryError:
            errorstring = ("\nNo data for: {}".format(ip) + "\n\n")
            print(errorstring)
            write_to_file(errorstring)

    # Handle invalid IP address entries
    except ValueError:
        print("Please enter a valid IP address")


def check_virustotal(ip, multiple):

    # Check Virus Total for IP details - NOTE: prerequisite is file called vtapikey.txt
    print("Checking Virustotal FREE - only 4 IPs per minute. Updates every 15 seconds.")

    # Get API key or throw error if not found
    try:

        # Open api key file and read the key
        with open('vtapikey.txt') as f:
            apikey = f.readline()

            # URL for Virustotal IP-Address Report
            url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

            # Set parameters for API call
            params = {'apikey': apikey, 'ip': ip}

            # Get response
            response = requests.get(url, params=params)

            # Prep details for writeout
            details = response.json()

            # Get list length and if the list contains items, iterate over the list
            # Note that we are collecting detected urls, but this can be any of the items that the
            # Virustotal API returns
            length = len(details["detected_urls"])
            if length != 0:
                print("\n\nVirustotal detected malicious URLs tied to {}:\n".format(ip))
                for url in range(length):
                    print(details["detected_urls"][url])

                    # Check if there are multiple IPs to investigate, print details to file if so
                    if multiple:
                        write_to_file(str(details["detected_urls"][url])+"\n")

            # Share if Virustotal is clean and no malicious URLs are tied to IP
            else:
                print("No URLs detected in Virustotal for: {}\n".format(ip))

                # Write that information to file if multiple IPs are being checked.
                if multiple:
                    write_to_file("No URLs detected in Virustotal for: {}\n".format(ip))

    # Deal with error if API key file is not found.
    except IOError:
        print("Please make sure vtapikey.txt exists and has legitimate Virustotal API key")


def write_to_file(details):

    # Write to default file name
    with open(outputfile, "a+") as outfile:
        outfile.write(details)
        outfile.close()


# Program start
if __name__ == '__main__': parse_arguments()

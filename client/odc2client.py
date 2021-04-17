#!/usr/bin/env/python3
import dns.resolver

# colorize output
OV = '\x1b[0;33m' # verbose
OR = '\x1b[0;34m' # routine
OE = '\x1b[1;31m' # error
OM = '\x1b[0m'    # mischief managed

# answers = dns.resolver.query('dnspython.org', 'MX')
# for rdata in answers:
#     print('Host', rdata.exchange, 'has preference', rdata.preference)

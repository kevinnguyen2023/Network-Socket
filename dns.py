#!/usr/bin/env python3

# Python DNS query client
#
# Example usage:
#   ./dns.py --type=A --name=www.pacific.edu --server=8.8.8.8
#   ./dns.py --type=AAAA --name=www.google.com --server=8.8.8.8

# Should provide equivalent results to:
#   dig www.pacific.edu A @8.8.8.8 +noedns
#   dig www.google.com AAAA @8.8.8.8 +noedns
#   (note that the +noedns option is used to disable the pseduo-OPT
#    header that dig adds. Our Python DNS client does not need
#    to produce that optional, more modern header)


from dns_tools import dns  # Custom module for boilerplate code
from dns_tools import dns_header_bitfields

import argparse
import ctypes
import random
import socket
import struct
import sys

def main():

    # Setup configuration
    parser = argparse.ArgumentParser(description='DNS client for ECPE 170')
    parser.add_argument('--type', action='store', dest='qtype',
                        required=True, help='Query Type (A or AAAA)')
    parser.add_argument('--name', action='store', dest='qname',
                        required=True, help='Query Name')
    parser.add_argument('--server', action='store', dest='server_ip',
                        required=True, help='DNS Server IP')

    args = parser.parse_args()
    qtype = args.qtype
    qname = args.qname
    server_ip = args.server_ip
    port = 53
    server_address = (server_ip, port)

    if qtype not in ("A", "AAAA"):
        print("Error: Query Type must be 'A' (IPv4) or 'AAAA' (IPv6)")
        sys.exit()

    # Create UDP socket
    # ---------
    # STUDENT TO-DO
    # ---------
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Generate DNS request message
    # ---------
    # STUDENT TO-DO
    # ---------
    print("Sending request for" + qname + ", type " + qtype + ", to server " + server_ip + ", port %d" %port)
    
    transID = random.randrange(0,65535,1) #Random port
    Questions = 1
    Answer = 0
    Authority = 0
    Additional = 0
    flags = 288
    
    site = qname.split(".")
    raw_bytes = bytearray()
    raw_bytes =  struct.pack("!HHHHHH", transID,flags, Questions, Answer, Authority, Additional) + raw_bytes
        
    for domain in site:
    	raw_bytes += struct.pack("!B", len(domain))
    	raw_bytes += bytes(domain, 'ascii')
    	
    	
    raw_bytes += struct.pack("!B", 0)
    
    if qtype == "A":
    	raw_bytes = raw_bytes + struct.pack("!H", 1)
    else:
    	raw_bytes = raw_bytes + struct.pack("!H", 28)
    	
    raw_bytes = raw_bytes + struct.pack("!H", 1)

    # Send request message to server
    # (Tip: Use sendto() function for UDP)
    # ---------
    # STUDENT TO-DO
    # ---------
    sock.sendto(raw_bytes, server_address)

    # Receive message from server
    # (Tip: use recvfrom() function for UDP)
    # ---------
    # STUDENT TO-DO
    # ---------
    
    (bytes1, src_addr) = sock.recvfrom(4096)

    # Close socket
    # ---------
    # STUDENT TO-DO
    # ---------
    
    sock.close()


    # Decode DNS message and display to screen
    dns.decode_dns(bytes1)


if __name__ == "__main__":
    sys.exit(main())

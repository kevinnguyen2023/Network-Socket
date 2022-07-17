__author__ = 'jshafer'

import ctypes
import socket
import struct

class dns_header_bitfields(ctypes.BigEndianStructure):
    _fields_ = [
        ("qr", ctypes.c_uint16, 1),
        ("opcode", ctypes.c_uint16, 4),
        ("aa", ctypes.c_uint16, 1),
        ("tc", ctypes.c_uint16, 1),
        ("rd", ctypes.c_uint16, 1),
        ("ra", ctypes.c_uint16, 1),
        ("reserved", ctypes.c_uint16, 3),
        ("rcode", ctypes.c_uint16, 4)
    ]

class dns():

    # Convert response code to string
    def rcode_to_str(rcode):
        if rcode == 0:
            return "No error"
        elif rcode == 1:
            return "Format error (name server could not interpret your request)"
        elif rcode == 2:
            return "Server failure"
        elif rcode == 3:
            return "Name Error (Domain does not exist)"
        elif rcode == 4:
            return "Not implemented (name server does not support your request type)"
        elif rcode == 5:
            return "Refused (name server refused your request for policy reasons)"
        else:
            return "WARNING: Unknown rcode"

    # Convert query type to string
    def qtype_to_str(qtype):
        if(qtype == 1):
            return "A"
        elif(qtype == 2):
            return "NS"
        elif(qtype == 5):
            return "CNAME"
        elif(qtype == 15):
            return "MX"
        elif(qtype == 28):
            return "AAAA"
        else:
            return "WARNING: Record type not decoded"

    # Convert query class to string
    def class_to_str(qclass):
        if(qclass == 1):
            return "IN"
        else:
            return "WARNING: Class not decoded"

    def decode_dns(raw_bytes):

        # OLD SOLUTION:
        #response_header = dns_header()
        #response_header.from_bytearray(raw_bytes[0:12])


        print("Server Response")
        print("---------------")

        # Print out the message header
        # ----------------------------------
        bitfields = dns_header_bitfields()
        bitfields_raw = bytearray()
        (hdr_message_id,
         bitfields_raw,
         hdr_qdcount,
         hdr_ancount,
         hdr_nscount,
         hdr_arcount) = struct.unpack("!H2sHHHH", raw_bytes[0:12])

        ctypes.memmove(ctypes.addressof(bitfields), bitfields_raw, 2)

        print("Message ID: %i" % hdr_message_id)
        print("Response code: %s" % dns.rcode_to_str(bitfields.rcode))
        print("Counts: Query %i, Answer %i, Authority %i, Additional %i" %
              (hdr_qdcount, hdr_ancount, hdr_nscount, hdr_arcount))

        # Print out each question header
        # ----------------------------------
        offset = 12
        for x in range(0, hdr_qdcount):
            qname = ""
            start = True
            while True:
                qname_len = struct.unpack("B",raw_bytes[offset:offset+1])[0]
                if(qname_len == 0):
                    offset += 1
                    break  # Finished parsing out qname
                elif(not start):
                    qname += "."
                qname += raw_bytes[offset+1:offset+1+qname_len].decode()
                offset += 1+qname_len
                start = False

            (qtype, qclass) = struct.unpack("!HH", raw_bytes[offset:offset+4])

            print("Question %i:" % (x+1))
            print("  Name: %s" % qname)
            print("  Type: %s" % dns.qtype_to_str(qtype))
            print("  Class: %s" % dns.class_to_str(qclass))

            offset += 4

        # Print out each answer header
        # ----------------------------------
        for x in range(0, hdr_ancount):
            (aname, atype, aclass, attl, ardlength)\
                = struct.unpack("!HHHIH", raw_bytes[offset:offset+12])

            if(atype == 1):
                aaddr = socket.inet_ntop(socket.AF_INET, raw_bytes[offset+12:offset+12+4]) + " (IPv4)"
                offset += 12 + 4
            elif(atype == 28):
                aaddr = socket.inet_ntop(socket.AF_INET6, raw_bytes[offset+12:offset+12+16]) + " (IPv6)"
                offset += 12 + 16
            else:
                aaddr = "WARNING: Addr format not IPv4 or IPv6"

            print("Answer %i:" % (x+1))
            print("  Name: 0x%x" % aname)
            print("  Type: %s, Class: %s, TTL: %i" %
                  (dns.qtype_to_str(atype), dns.class_to_str(aclass), attl))
            print("  RDLength: %i bytes" % ardlength)
            print("  Addr: %s" % aaddr)
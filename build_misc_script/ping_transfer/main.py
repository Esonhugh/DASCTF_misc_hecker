#!/usr/bin/env python
# -*- encoding=utf8 -*-

# send file with ICMP inet with low rate limit.ls

import os
import socket
import struct
import sys
import time

# PREFIX + file data + SUFFIX
PREFIX = b"\xEE\x55\x00N\xde\xad\xbe\xef"
SUFFIX = b"\x13\x37\x13\x37\x11\x33\x33\x77"
rate_limit = 3

def calculate_checksum(icmp):
    if len(icmp) % 2:
        icmp += b'\00'
    checksum = 0
    for i in range(len(icmp)//2):
        word, = struct.unpack('!H', icmp[2*i:2*i+2])
        checksum += word
    while True:
        carry = checksum >> 16
        if carry:
            checksum = (checksum & 0xffff) + carry
        else:
            break
    checksum = ~checksum & 0xffff
    return struct.pack('!H', checksum)

"""
def calculate_checksum(icmp):
    highs = icmp[0::2]
    lows = icmp[1::2]
    checksum = ((sum(highs) << 8) + sum(lows))

    while True:
        carry = checksum >> 16
        if carry:
            checksum = (checksum & 0xffff) + carry
        else:
            break

    checksum = ~checksum & 0xffff

    return struct.pack('!H', checksum)
"""

def pack_icmp_echo_request(ident, seq, payload):
    pseudo = struct.pack(
        '!BBHHH',
        8,
        0,
        0,
        ident,
        seq,
    ) + payload
    checksum = calculate_checksum(pseudo)
    # print("PAD: ",pseudo[:2]+checksum+pseudo[4:])
    return pseudo[:2] + checksum + pseudo[4:]

def unpack_icmp_echo_reply(icmp):
    _type, code, _, ident, seq, = struct.unpack(
        '!BBHHH',
        icmp[:8]
    )
    if _type != 0:
        return
    if code != 0:
        return

    payload = icmp[8:]

    return ident, seq, payload

def send_routine(sock, addr, ident, magic, stop):
    # first sequence no
    seq = 1

    while not stop:
        # currrent time
        sending_ts = time.time()

        # packet current time to payload
        # in order to calculate round trip time from reply
        payload = struct.pack('!d', sending_ts) + magic

        # pack icmp packet
        icmp = pack_icmp_echo_request(ident, seq, payload)

        # send it
        sock.sendto(icmp, 0, (addr, 0))
        seq += 1
        time.sleep(1)

def send_once(sock, addr, ident, magic, seq):
    # first sequence no
    # currrent time
    sending_ts = time.time()
    # packet current time to payload
    # in order to calculate round trip time from reply
    payload = struct.pack('!d', sending_ts) + PREFIX + magic + SUFFIX
    # pack icmp packet
    icmp = pack_icmp_echo_request(ident, seq, payload)
    # send it
    sock.sendto(icmp, 0, (addr, 0))
    time.sleep(rate_limit)

def recv_routine(sock, ident, magic):
    while True:
        # wait for another icmp packet
        ip, (src_addr, _) = sock.recvfrom(1500)

        # unpack it
        result = unpack_icmp_echo_reply(ip[20:])
        if not result:
            continue

        # print info
        _ident, seq, payload = result
        if _ident != ident:
            continue

        sending_ts, = struct.unpack('!d', payload[:8])
        print('%s seq=%d %5.2fms' % (
            src_addr,
            seq,
            (time.time()-sending_ts) * 1000,
        ))


# generate
def read_file_by_size(filename,size):
    with open(filename,"rb") as f:
        while True:
            chunk = f.read(size)
            if not chunk:
                return
            yield chunk

def ping(addr,sendfile):
    # create socket for sending and receiving icmp packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # id field
    ident = os.getpid()
    # magic string to pad

    magic2 = read_file_by_size(sendfile,1000)
    seq = 1
    for payload in magic2:
        send_once(sock,addr,ident,payload,seq)
        print(payload)
        seq += 1

    # sender thread stop flag
    # append anything to stop
    sender_stop = []

    # start sender thread
    # call send_routine function to send icmp forever
    # args = (sock, addr, ident, magic, sender_stop,)
    # sender = threading.Thread(target=send_routine, args=args)
    # sender.start()

    """
    try:
        # receive icmp reply forever
        recv_routine(sock, ident, magic)
    except KeyboardInterrupt:
        pass
    """

    # tell sender thread to stop
    # sender_stop.append(True)

    # clean sender thread
    # sender.join()

    print()

if __name__ == '__main__':
    lens = sys.argv.__len__()
    if lens not in [3,4]:
        print("Usage:", sys.argv[0],"{ip} {sendfile}")
        print("Usage:",sys.argv[0],"{ip} {sendfile} {ratelimit (second)}")

    if lens == 4:
        rate_limit = int(sys.argv[3])

    ping(sys.argv[1], sys.argv[2])

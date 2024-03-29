#!/usr/bin/env python2.7

import math
import os
import sys

from Crypto.PublicKey import *
from Crypto.Util.number import *
from pwn import *


e = 65537
upper_limit = 1 << 512
lower_limit = 0

while True:
    p = process('./encrypt.py')
    # p = remote('18.217.237.201', 3197)

    p.recvline()
    cipher = p.recvline().split()[-1]
    modulus = p.recvline().split()[-1]
    for i in range(3):
        p.recvline()
    if len(cipher) % 2:
        cipher = '0' + cipher
    cipher = bytes_to_long(cipher.decode('hex'))
    modulus = int(modulus)

    upper_limit = min(upper_limit, modulus)

    factor = 2
    midpoint = modulus / factor
    while not lower_limit < midpoint < upper_limit:
        factor *= 2
        if midpoint < lower_limit:
            midpoint += modulus / factor
        elif midpoint > upper_limit:
            midpoint -= modulus / factor
        else:
            raise Error('search fail')

    query = (cipher * pow(factor, e, modulus)) % modulus
    query = '2\n' + long_to_bytes(query).encode('hex') + '\n'
    p.send(query)

    result = int(p.recvline()[-2])

    if result:  # odd
        lower_limit = int(midpoint)
        print('up')
    else:
        upper_limit = int(midpoint)
        print('down')

    print 'Remaining bits:', int(math.log(upper_limit - lower_limit, 2))
    print long_to_bytes(midpoint)

    p.close()
    if upper_limit - lower_limit < 2:
        quit()

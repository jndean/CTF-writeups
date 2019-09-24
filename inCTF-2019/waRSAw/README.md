# waRSAw (711 points, 18 solves)

We are given a program encrypt.py and the address of a server running the program.
Upon connection, the program generates a new RSA key and uses it to encrypt the flag, then sends this and the public modulus back to us. It then presents two options: [1] encrypt and return a client-provided value using the current key, or [2] decrypt a client-provided value and return the parity (LSB) of the plaintext.


```Welcome to RSA encryption oracle!
Here take your flag (in hex):  3bca234bc42e7bad6ddfb34087379d61a641b3d479ab81a1596dd0039d494a2f2dac34a84ea164d4d32c71b4c1c4f0fc8578a2351d56835ca5e29c10c7159aa2a06fccb04f6a78b2bad9f6ae6a5a2d28d517e2db1b4afa32c1ad7069ac911efe0c613f549feddd999654564962efca072eafc00513fb787accaaa669ea43cab3
Here take modulus:  92401869837306977294650062841998549939040887700291715753752856697480103414693811412477653726273704373726166706255039340501057500321883555397456175481567491772576064447048367968512697492739285702706678102637780437395436063586692324627652276064622882449368388496256736344111756633249154600280404636361369082973
RSA service
[1] Encrypt
[2] Decrypt
Enter your choice: 2
Enter the ciphertext you want to decrypt (in hex): 3bca234bc42e7bad6ddfb34087379d61a641b3d479ab81a1596dd0039d494a2f2dac34a84ea164d4d32c71b4c1c4f0fc8578a2351d56835ca5e29c10c7159aa2a06fccb04f6a78b2bad9f6ae6a5a2d28d517e2db1b4afa32c1ad7069ac911efe0c613f549feddd999654564962efca072eafc00513fb787accaaa669ea43cab3
Here take your plaintext (in hex):  00
```

There exists a well-known LSB Oracle attack for RSA, explained in detail [here](https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-LSBit-Oracle).

In short, for modulus `n=p*q`, exponent `e`, secret plaintext `P` and ciphertext `C`, i.e. `P^e = C (mod n)`, we know `e`, `C` and `n`. Thus we can compute `2^e * C = 2^e * P^e = 2P^e (mod n)`, ask the Oracle (server) to decrypt this and return the parity of `2P (mod n)`. We know that
1. `P < n`, otherwise encryption would be lossy due to mod
2. `n` is odd, it is the product of two big primes
3. `2P` is even

So `2P (mod n)` is even if and only if `P < n/2`, narrowing the possible values of `P` by half.

Repeating the process, decrypting `2^e * 2^e * C (mod n)` we can get the parity of `4P (mod n)` which has another factor of two and hence will be even if and only if `0 < P < n/4` or `3n/4 < P < n` (I am not being careful with inclusive bounds). Combined with the information from the first step we have reduced the range of possible values of `P` by a factor of 4. Continuing (on step `i` computing `2^ie * C (mod n)`), we may iteratively half the possible values of `P` until after about `log_2(n)` requests we recover the plaintext.

The twist in this challenge comes from the fact that a new key is generated for every connection, and we may only request one decrypt per connection. Therefore we must generalise the solution.

Convince yourself that, on step `i+1` above, the LSB oracle gives us the ability to divide the range `[0, n]` evenly into `2^i` sub-ranges and ask whether `P` lies in the lower half or upper half of any of those sub-ranges. Now, since we have a different `n` on each connection, our sub-ranges don't line up nicely with the ranges from the previous step. But that's fine.

We simply maintain a running lower and upper bound on `P`, called `L` and `U` resp. In each iteration, given an `n`, we compute `i` such that both these bounds lie inside one of the `2^i` even partitions of `[0, n]` and that the halfway point inside this partition lies between `L` and `U`. Then we request the parity of the decryption of `2^((i+1)*e) * c (mod n)`, telling us whether `P` lies above or below the midpoint, and update either our upper or lower bound accordingly. Thus each step we further restrict the range of possible values of `P` by half on average (well maybe not exactly due to how moduli are distributed?). The relevant part of one step in the attack code is shown below.

```
factor = 2
midpoint = modulus / factor
while not (midpoint > lower_limit and midpoint < upper_limit):
    factor *= 2
    if midpoint < lower_limit:
        midpoint += modulus / factor
    elif midpoint > upper_limit:
        midpoint -= modulus / factor

query = (cipher * pow(factor, e, modulus)) % modulus

# ... ask server to decrypt query and return parity ... #

if odd:
    lower_limit = int(midpoint)
else:
    upper_limit = int(midpoint)

print long_to_bytes(midpoint)
```

The flag was padded at the start and end to make the search a bit more interesting, but the end-padding in particular actually helped because deducing the final few bits of the plaintext would have required much more careful handling of bounds than I used. The exploit script prints a value within the range of possiblities as bytes every step, so we can see when enough of the flag has emerged to finish (leaving about 145 bits of uninteresting plaintext unrecovered)

```
Remaining bits: 147
flag: inctf{w0w_$0_coOl_LSbit_|3r0\x81\xb7\x9fJzZ�D\x942\x0f\x12sK�5s\x96
Remaining bits: 146
flag: inctf{w0w_$0_coOl_LSbit_|3r0\x7f/\x9b\x06媜\x97\x98#\x7f�c\xb0\�>k\x85
Remaining bits: 146
flag: inctf{w0w_$0_coOl_LSbit_|3r0x\x06\x85\xa7\xb0&�5q����k\xa5�:'
Remaining bits: 145
flag: inctf{w0w_$0_coOl_LSbit_|3r0{|���\x12\x94\x92\x85�h5�\��D\x11
Remaining bits: 145
flag: inctf{w0w_$0_coOl_LSbit_|3r0}+Kڒ)�"��\xa9�����im
```

The full attack script is waRSAaw.py, and runs pretty quick attacking a local process rather than a busy CTF server.
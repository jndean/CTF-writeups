# Pass The Hash (50 points, 21 solves)

"Mixing many secure hashes yields more security! The password should be safe."

## Description

We are given script ph.py which is running on the challenge server. On each connection it generates 20 bytes of random password. It then allows the client to send up to 1024 salt values, each of which it will hash  with the password and return. After this, the server sends one random challenge salt to the client, and asks the client what the result of the salted hash of the (still secret) password will be. If the client is correct they are sent the flag in plaintext.

## Analysis
The password and challenge salt are generated sensibly enough. However, this is the combo hash function used

```
# List of hash functions
h_list =  [sha, sha1, ripemd160, sha256]

def xor(s1,s2):
	return ''.join([chr(ord(s1[i]) ^ ord(s2[i % len(s2)])) for i in range(len(s1))])

def combo_hash(salt, password):
	salted_pass = password + salt + password
	l_pass = salted_pass[:32]
	r_pass = salted_pass[32:]
	for i in range(16):
		l_index = ord(l_pass[31]) % len(h_list)
		r_index = ord(r_pass[0]) % len(h_list)
		l_hash = h_list[l_index](l_pass)
		r_hash = h_list[r_index](r_pass)
		l_pass = xor(l_pass,r_hash)
		r_pass = xor(r_pass,l_hash)
	return l_pass + r_pass
```

The salt is 24 characters, and it is sandwiched by two copies of the password making a 64-byte array, split into two 32-byte halves called l_pass and r_pass. The right-most byte of l_pass is used to determine what hash algorithm is applied to r_pass, and the left-most byte of r_pass determines the algorithm for l_pass. These two hashes are then xor'd back on, but onto the opposite half they came from. Doing so randomises what hash will be chosen in the next round of hashing. This is repeated for 16 rounds in place, then the whole 64-byte string is returned as the hash.

 The weakness here comes from the choice of hashing algorithms. sha, sha1 and ripemd160 all return 20-byte hashes, only sha256 returns the 32-characters necessary to cover a whole half of the array. When given a second argument shorter than the first, the xor implementation here repeats bytes up to full length. Hence if one of the short hashes is used on a half, the first and last 12 bytes of that half will have been xor'd with the same thing. Since there are 3 short hash algorithms and they are chosen effectively at random based on they state of the other half, on each of the 16 rounds in this function there is a 3/4 chance of this happening, apart from on the first round where we contol the middle characters (they're in the salt we supply) and so can guarentee a short choice. Hence on each half there is a `(3/4)^15 = 1.3%` chance that what is returned to us used a short hash every round. We are allowed to request 1024 hashes from the server in the opening phase, which is more than enough to recieve a few such degenerate halves. If we xor the first and last 12 bytes of a weak half, all 16 rounds of hash will cancel and we will get the xor of 12 bytes of the password together with 12 bytes of the salt (which 12 depends on which half we're talking about). We know the salt, so we may compute 12 bytes of the password. However the password is random data so we will not be able to recognise when we have gotten lucky. Fortunately the left half can give us the first 12 bytes of password and the right half can give us the last 12 bytes, and the password is only 20 bytes, so if what they give us has 4 bytes of overlap we're likely in the money.
 

```
h = p.recvline()[:-1].decode('hex')

right_plain_salt = xor(h[32:44], h[-12:])
left_plain_salt = xor(h[:12], h[20:32])
right_plain = xor(right_plain_salt, right_salt)
left_plain = xor(left_plain_salt, left_salt)

if left_plain[-4:] == right_plain[:4]:
    password = left_plain + right_plain[4:]
```

Of course, the probability that *both* halves are weak in the same hash is only `((3/4)^2)^15 = 0.018%` meaning after  1024 hashes there's only an 18% chance of finding the password. Running the attack 5 or so times until it works is absolutely feasible but not necessary. The attack script instead keeps a record of all potential plaintext parts, and checks new options for overlap with previous possibilities from the other half, putting us back in `(3/4)^15` territory. 

```
left_overlap = left_plain[-4:]
right_overlap = right_plain[:4]
left_dict[left_overlap] = left_plain
right_dict[right_overlap] = right_plain

if left_overlap in right_dict:
    password = left_plain + right_dict[left_overlap][4:]
elif right_overlap in left_dict:
    password = left_dict[right_overlap] + right_plain[4:]
```

Once we have the password, we can compute the correct response to the challenge salt and receive the flag.

``` 
[+] Opening connection to 52.142.217.130 on port 13374: Done
Greetings! Give me some salts and I will give you some hashes
Give me the challenge_hash Congrats. Here's a flag for you:
PTBCTF{420199e572e685af8e1782fde58fd0e9}
[*] Closed connection to 52.142.217.130 port 13374
```

The attack script is solve.py.
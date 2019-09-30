import pwn
from random import randrange as rng
import ph


# p = pwn.remote('52.142.217.130', 13374)
p = pwn.process('./ph.py')
print(p.recvline())


def xor(s1, s2):
    return ''.join([chr(ord(s1[i]) ^ ord(s2[i % len(s2)]))
                    for i in range(len(s1))])


def make_salt_halves(val):
    left = hex(val)[2:][::-1]
    left += '0' * (24-len(left))
    right = '0' * 24
    return left, right


def get_flag(password, p):
    p.send('\n')
    p.recvline()
    salt = p.recvline()[:-1].decode('hex')
    response = ph.combo_hash(salt, password, ph.h_list, ph.no_rounds)
    p.send(response.encode('hex') + '\n')
    print p.recvuntil('}') # interactive()
    quit()


left_dict, right_dict = {}, {}

seed = rng(102400)
for i in range(seed, seed+1024):

    left, right = make_salt_halves(i)

    p.send(left + right + '\n')
    h = p.recvline()[:-1].decode('hex')

    right_plain = xor(h[32:44], h[-12:])
    left_plain = xor(xor(h[:12], h[20:32]), left.decode('hex'))

    left_overlap = left_plain[-4:]
    right_overlap = right_plain[:4]
    left_dict[left_overlap] = left_plain
    right_dict[right_overlap] = right_plain

    if left_overlap in right_dict:
        password = left_plain + right_dict[left_overlap][4:]
        get_flag(password, p)

    if right_overlap in left_dict:
        password = left_dict[right_overlap] + right_plain[4:]
        get_flag(password, p)


# PTBCTF{420199e572e685af8e1782fde58fd0e9}

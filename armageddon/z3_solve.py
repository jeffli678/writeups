from z3 import *

n = 41
passwd = [BitVec('s_%d' % i, 32)  for i in range(n)]

s = Solver()
for i in range(n):
    s.add(passwd[i] >= 0x21)
    s.add(passwd[i] <= 127)

s.add(passwd[1] * passwd[0x27] * passwd[0x15] + passwd[0x11] + passwd[0x13] * passwd[0x1e] == 0xdb11e)
s.add(passwd[0x25] - passwd[0x13] * passwd[0xc] == -0xc0c)
s.add(((passwd[2] - passwd[0x1f]) + passwd[0x21] * passwd[0xd] * passwd[0x14]) - passwd[0x11] == 0xebd1d)
s.add((passwd[7] + passwd[0x24] * passwd[0xf]) - passwd[0x1d] * passwd[0x22] == 0x18e5)
s.add((passwd[0x15] - passwd[0x1b] * passwd[0xf]) - passwd[0x11] == -0x2e3b)
s.add(((passwd[0xf] - passwd[0x25] * passwd[8]) - passwd[5]) - passwd[6] == -0x19a5)
s.add(((passwd[0x23] + passwd[0x1d]) - passwd[0x14]) + passwd[0x1a] == 0xc4)
s.add(passwd[7] * passwd[0x20] + passwd[0x1f] * passwd[0xb] == 0x45ca)
s.add(passwd[0x1d] * passwd[0x18] * passwd[0x24] + passwd[0x25] == 0xac3fb)
s.add(((passwd[8] - passwd[0x10]) - passwd[0xc]) + passwd[0x28] + passwd[0xf] == 0xd0)
s.add((passwd[0x23] * passwd[0x11] * passwd[0x0] - passwd[0xb]) + passwd[0xc] * passwd[7] * passwd[0x26] == 0x172e48)
s.add(((passwd[0x1a] - passwd[0xd]) + passwd[3] * passwd[8]) - passwd[5] == 0x10b8)
s.add(passwd[3] + passwd[0x11] + passwd[0x24] + passwd[0x14] == 0x160)
s.add((passwd[0x1a] - passwd[0x15] * passwd[0x12]) + passwd[0x1b] * passwd[0x19] == 0x8a2)
s.add((passwd[0x22] - passwd[0xe]) + passwd[5] * passwd[0x21] + passwd[0x23] == 0x1bd8)
s.add(passwd[5] * passwd[8] * passwd[0x26] * passwd[0x19] + passwd[0x15] + passwd[0x23] == 0x2ca6988)
s.add((passwd[8] * passwd[8] + passwd[0x15] * passwd[0xc]) - passwd[0x24] == 0x2430)
s.add((((passwd[0x23] + passwd[2]) - passwd[7]) - passwd[9] * passwd[0x12]) + passwd[2] * passwd[0x27] == 0x2de)
s.add(((passwd[5] * (passwd[0x11] - 1) - passwd[6]) - passwd[0x14]) - passwd[0x22] * passwd[0x17] == -0x11d5)
s.add((passwd[0x22] - passwd[0xb]) + passwd[0xb] * passwd[0xd] == 0x2aba)
s.add((passwd[0x22] - passwd[0xb]) + passwd[0xb] * passwd[0xd] == 0x2aba)
s.add(passwd[0x1b] + passwd[0x12] * passwd[0xf] + passwd[0x20] + passwd[9] == 0x2668)
s.add(passwd[0x15] - passwd[0xe] * passwd[0x1d] == -0x1400)
s.add((((passwd[9] * passwd[9] - passwd[10]) + passwd[0xd]) - passwd[0x24]) - passwd[0x14] == 0x19ac)
s.add(((passwd[0xc] + passwd[2] + passwd[0x22]) - passwd[4] * passwd[0x14] * passwd[0x17]) + passwd[0x16] == -0xafa0c)
s.add(((passwd[4] + passwd[5]) - passwd[10]) + passwd[0x1b] == 0xb4)
s.add(((passwd[0xf] - passwd[0x1c]) - passwd[0x25]) - passwd[0x18] * passwd[0x12] * passwd[0x0] == -0xd06e8)
s.add(((passwd[4] * passwd[0x23] + passwd[0x19]) - passwd[0x15]) - passwd[0x18] * passwd[0x14] == -0x1f8)
s.add((((passwd[0x19] + passwd[10]) - passwd[0xf]) + passwd[0x1c]) - passwd[0x21] == 0x3e)
s.add((((passwd[6] - passwd[0x19]) + passwd[2]) - passwd[0x19]) + passwd[1] + passwd[0x12] * passwd[0x1c] == 0x1eb9)
s.add(passwd[0xb] * (passwd[5] + passwd[0x22] * passwd[0x16]) + passwd[0xc] + passwd[0x22] == 0x121b93)
s.add((((passwd[3] + passwd[0xe]) - passwd[0x26]) - passwd[0xd]) - passwd[1] == -0x80)
s.add((((passwd[0x1e] + passwd[0x15]) - passwd[0x11]) - passwd[0x17] * passwd[5]) + passwd[0x21] == -0x1afd)
s.add((passwd[7] - passwd[0xe]) + passwd[0x11] + passwd[0x21] == 0xdf)
s.add((passwd[8] - passwd[3]) + passwd[2] * passwd[10] * passwd[10] == 0x626e2)
s.add(((passwd[0x25] + passwd[7]) - passwd[0x13]) + passwd[0xc] + passwd[0xb] == 0x12f)
s.add(passwd[1] + passwd[8] * passwd[0x14] + passwd[0x20] + passwd[0xf] == 0x167a)
s.add((passwd[0x11] - passwd[4]) - passwd[0x1d] * passwd[0x12] == -0x11ca)
s.add((passwd[0xd] * passwd[0x16] - passwd[10]) - passwd[0x23] == 0x32e9)
s.add(passwd[0xd] + passwd[0xb] + passwd[0x1d] * passwd[0x13] == 0xec9)
s.add((((passwd[0x19] + passwd[0x26] * passwd[0xf]) - passwd[0xb]) + passwd[0x20]) - passwd[0x15] * passwd[0x22] == 0x2a)
s.add(passwd[6] * passwd[9] + passwd[0x23] == 0xedd)

if s.check() == sat:
    print('solved!')
    m = s.model()
    flag = ''
    for i in range(n):
        c = m[passwd[i]].as_long()
        flag += chr(c)
    print(flag)
else:
    print('failed')

# UMDCTF-{ARM_1s_s0_SATisfying_7y8fdlsjebn}
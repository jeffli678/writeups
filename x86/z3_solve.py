from z3 import *

# extracted from the challenge binary
init_val = 0x3df2f794
target_val = 0x7a612770
constants = [
    0x52ae22f2,
    0xbf409bcc,
    0x46417dc1,
    0x25f7d9a1,
    0xef83a7ce,
    0x2dd63e8e,
    0x584a1ec5,
    0x8e58e1df,
    0xf2705f70,
    0x2e94ef1e,
    0x3ca9e080,
    0xa617b5df,
    0x29ae9c3d,
    0x7461ed52,
    0x7125faac,
    0x65dfffd6,
    0x97f1f41c,
    0x6f4e0648,
    0xd803e5d0,
    0xf358f0eb,
    0xbc3b30c7,
    0x585685f8,
    0x2a9cc47c,
    0x7f03d175,
    0xc1d942ae,
    0x174c7d4f,
    0xb7d004f0,
    0xbec8b077,
    0x8ce8eaa2,
    0x2510e330,
    0x4aed0eee,
    0x4043cd91
]

# solver script
n = 32
inputs = [Bool('bit_%d' % i) for i in range(n)]

val = BitVecVal(init_val, 32)
for i in range(n):
    val = If(inputs[i], val + constants[i], val - constants[i])

s = Solver()
s.add(val == BitVecVal(target_val, 32))

if s.check() == sat:
    print('solved')
    m = s.model()
    solution = 0
    for i in range(n):
        bit = m.evaluate(inputs[i])
        if bit:
            solution |= (1 << i)
    print(solution)
else:
    print('failed')

#  $ python z3_solve.py 
# solved
# 2371132652

#  $ ./x86
# 2371132652
# Well done!
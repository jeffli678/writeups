import random
import os

rounds = 32
MAXINT = 0xffffffff

output = open('code.h', 'w')

val = random.randint(0, MAXINT)
# mov eax, val
output.write('{0xb8, 0x%x},\n' % val)
ans = 0

for i in range(rounds):
    op = random.randint(0, 1)
    round_val = random.randint(0, MAXINT)
    ans |= (op << i)
    if op == 0:
        val -= round_val
    else:
        val += round_val

    val &= MAXINT
    
    junk_opcode = random.randint(0, 0xff)
    output.write('{0x%x, 0x%x},\n' % (junk_opcode, round_val))

# cmp eax, val
output.write('{0x3d, 0x%x},' % val)
output.close()

print('the answer is: %d' % ans)
os.system('make')

# 1804139300
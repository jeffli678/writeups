import angr
import claripy

proj = angr.Project('./armageddon')
print(hex(proj.entry))
start_address = 0x14a88
state = proj.factory.entry_state(addr = start_address)

input_addr = 0xaa000000
r11 = input_addr + 0x34
state.regs.r11 = r11

n = 42
flag = state.solver.BVS('flag', n * 8)
state.memory.store(input_addr, flag)

simgr = proj.factory.simgr(state)
good = 0x1504c
simgr.explore(find = good,
        avoid = [
            0x10674,
            0x107c8,
            0x109ac,
            0x10b6c,
            0x10cf0,
            0x10ea4,
            0x11010,
            0x11190,
            0x11308,
            0x114a4,
            0x116a8,
            0x1185c,
            0x119c8,
            0x11b84,
            0x11d38,
            0x11f10,
            0x120c4,
            0x122e4,
            0x124c8,
            0x1264c,
            0x12800,
            0x12948,
            0x12b1c,
            0x12d30,
            0x12e9c,
            0x13070,
            0x13248,
            0x133e0,
            0x135f0,
            0x137d4,
            0x13970,
            0x13b50,
            0x13cbc,
            0x13e6c,
            0x14014,
            0x141c8,
            0x1434c,
            0x144c4,
            0x14648,
            0x1485c,
            0x149a0
        ]
        ) 

if simgr.found:
    solution_state = simgr.found[0]
    input1 = solution_state.solver.eval(flag, cast_to = bytes)
    print('flag: ', input1)
else:
    print('Counld not find flag')


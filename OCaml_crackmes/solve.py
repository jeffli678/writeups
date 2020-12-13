#!/usr/bin/python3
from binaryninja import *
import angr

bv = BinaryViewType.get_view_of_file('teenager.bndb')

basic_block_addrs = [
    0x402d4c,
    0x402cdc,
    0x402c6c,
    0x402c02,
    0x402ba2,
    0x402b3c,
    0x402ad2,
    0x402a6c,
    0x4029fc,
    0x40298c,
    0x402922,
    0x4028b2,
    0x402842,
    0x4027e2,
    0x402782,
    0x40271c,
    0x4026b2,
    0x40264c,
    0x4025e2,
    0x402582,
    0x402512
]

def find_llil_basic_block(llil_basic_blocks, addr):
    for llil_bbl in llil_basic_blocks:
        if llil_bbl[0].address == addr:
            return llil_bbl

def collect_info(bv, addr):

    bbl = bv.get_basic_blocks_at(addr)[0]
    
    edges = bbl.outgoing_edges
    good_addr = 0
    bad_addr = 0
    for edge in edges:
        if edge.type == BranchType.TrueBranch:
            good_addr = edge.target.start
        elif edge.type == BranchType.FalseBranch:
            bad_addr = edge.target.start
    
    func = bv.get_functions_containing(addr)[0]
    llil_basic_blocks = list(func.llil_basic_blocks)
    llil_bbl = find_llil_basic_block(llil_basic_blocks, addr)
    src = llil_bbl[0].operands[1].operands[0].operands[0]

    char_idx = 0
    if src.operation == LowLevelILOperation.LLIL_ADD:
        char_idx = src.operands[1].value.value

    rbx_value = 0
    value_set = llil_bbl[0].get_possible_reg_values('rbx')
    if value_set.type == RegisterValueType.ConstantValue:
        rbx_value = value_set.value
        rbx_value &= 0xffffffffffffffff

    return good_addr, bad_addr, char_idx, rbx_value

def angr_solve(addr, good_addr, bad_addr, char_idx, rbx_value):
    proj = angr.Project('./teenager')
    state = proj.factory.entry_state(addr = addr)
    # suppose the input string (ASCII) is stored at 0xaa000000
    input_addr = 0xaa000000
    state.regs.rax = input_addr
    state.regs.rbx = rbx_value
    flag = state.solver.BVS('flag', 8)
    state.memory.store(input_addr + char_idx, flag)
    simgr = proj.factory.simgr(state)
    simgr.explore(find = good_addr, avoid = [bad_addr])
    if simgr.found:
        solution_state = simgr.found[0]
        char_solution = solution_state.solver.eval(flag, cast_to = bytes)
        return True, char_solution
    else:
        False, None

def main():
    solution = [0] * 0x15
    for addr in basic_block_addrs:
        good_addr, bad_addr, char_idx, rbx_value = collect_info(bv, addr)
        print(hex(addr), hex(good_addr), hex(bad_addr), hex(char_idx), hex(rbx_value))
        solved, output = angr_solve(addr, good_addr, bad_addr, char_idx, rbx_value)
        if solved:
            print(hex(char_idx), output)
            solution[char_idx] = output.decode('ascii')

    flag = ''.join(solution)
    print(flag)

if __name__ == '__main__':
    main()

# 0CamL_Ints_Ar3_W4rped

# $ ./teenager 
# -= Montrehack =-
#    Teenager

# Enter Password: 0CamL_Ints_Ar3_W4rped

# [+] Success!
# FLAG-221fddd2bbf810be10d156b060b0eda5
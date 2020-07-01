from binaryninja import *
# from __future__ import print_function
from triton     import *
import struct
import re

arch = Architecture['x86']

def is_opaque_predicate(instr):

    tokens = instr.tokens
    if tokens[0].text == 'xor' and tokens[2].text == tokens[4].text:
        return True
    if tokens[0].text == 'sub' and tokens[2].text == tokens[4].text:
        return True   
    return False

def should_patch_to_always_branch(instr):

    tokens = instr.tokens
    opcode = tokens[0].text
    if opcode in ['je', 'jz']:
        return True

    return False

def should_patch_to_never_branch(instr):

    tokens = instr.tokens
    opcode = tokens[0].text
    if opcode in ['jne', 'jnz']:
        return True
        
    return False

def print_slice_result(slice_result):

    # print(slice_result)
    for addr, dis in sorted(slice_result.items()):
        # Here we display the comment to understand the correspondence
        # between an expression and its referenced instruction.
        print('[slicing] 0x%x: %s' % (addr, dis))
        # print(v)

def slice_expr(ctx, regExpr):

    # print(regExpr)

    slicing = ctx.sliceExpressions(regExpr)

    result = {}
    # print(slicing.items())
    for k, v in slicing.items():
        # print(type(v))
        # print(v.getReadRegisters())
        comment = v.getComment()
        print(comment)
        try:
            addr, dis = comment.split(': ')
            addr = int(addr, 16)
            result[addr] = dis
        except:
            pass
    
    # print_slice_result(result)
    return result



def init_triton():

    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    return ctx

def symbolize_regs(ctx):

    ctx.symbolizeRegister(ctx.registers.eax)
    ctx.symbolizeRegister(ctx.registers.ebx)
    ctx.symbolizeRegister(ctx.registers.ecx)
    ctx.symbolizeRegister(ctx.registers.edx)  
    # ctx.symbolizeRegister(ctx.registers.ebp)

def merge_dict(dict1, dict2):
    
    ret = dict1.copy()
    ret.update(dict2)
    # print(len(ret))
    
    return ret


# def further_taint_bbl_instrs(bv, bbl, addr_to_start_taint, reg_to_taint):
def further_taint_bbl_instrs(bv, bbl, instrs_to_taint):

    newly_tainted_instrs = {}
    all_addrs_to_taint = instrs_to_taint.keys()

    ctx = init_triton()
    symbolize_regs(ctx)

    pc = bbl.start
    for inst in bbl:
        tokens, inst_size = inst

        inst = Instruction()
        curr_pc = pc
        inst.setAddress(pc)
        inst_bytes = bv.read(pc, inst_size)
        inst.setOpcode(inst_bytes)
        pc += inst_size  

        ctx.processing(inst)
        for se in inst.getSymbolicExpressions():
            se.setComment(str(inst))

        if curr_pc in all_addrs_to_taint:

            # print('here')

            read_registers = inst.getReadRegisters()
            # print(read_registers)
            if type(read_registers) == tuple:
                read_registers = [read_registers]

            if len(read_registers) > 0:
                # print(hex(inst.getAddress()))
                for read_reg, ast in read_registers:
                    # print(read_reg.getName())
                    if read_reg.getName() == 'eax':
                        # print('here')
                        result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.EAX])
                        # print(result)
                        newly_tainted_instrs = merge_dict(newly_tainted_instrs, result)

                    if read_reg.getName() == 'ebx':
                        result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.EBX])
                        newly_tainted_instrs = merge_dict(newly_tainted_instrs, result)

                    if read_reg.getName() == 'ecx':
                        result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.ECX])
                        newly_tainted_instrs = merge_dict(newly_tainted_instrs, result)

                    if read_reg.getName() == 'edx':
                        result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.EDX])
                        newly_tainted_instrs = merge_dict(newly_tainted_instrs, result)

                    print('===============')

    return newly_tainted_instrs


# def further_taint_bbl_instrs(bv, bbl, instrs):
    # pass

def find_instrs_need_further_taint(bv, bbl, newly_tainted_instrs, all_instrs):

    instrs_need_further_taint = {}
    for addr in newly_tainted_instrs.keys():
        inst = all_instrs[addr]
        if inst.isMemoryRead():
            read_registers = inst.getReadRegisters()
            # print(read_registers)
            if type(read_registers) == tuple:
                read_registers = [read_registers]

            if len(read_registers) > 0:
                # print(hex(inst.getAddress()))
                for read_reg, ast in read_registers:
                    # print(read_reg.getName())
                    if read_reg.getName() in ['eax', 'ebx', 'ecx', 'edx']:
                        instrs_need_further_taint[addr] = all_instrs[addr]

    return instrs_need_further_taint

def is_inst_writes_reg(inst, reg):

    found = False
    write_registers = inst.getWrittenRegisters()
    if type(write_registers) == tuple:
        write_registers = [write_registers]

    if len(write_registers) > 0:
        # print(hex(inst.getAddress()))
        for read_reg, ast in write_registers:
            if read_reg.getName() == reg:
                found = True
                break
    
    return found

def simplify_bbl(bv, bbl):


    ctx = init_triton()
    symbolize_regs(ctx)

    # ctx.symbolizeMemory(MemoryAccess(0, 4))
    # ctx.symbolizeMemory(MemoryAccess(0x2b918004, 4))

    # bv.begin_undo_actions()

    # make a copy of all instructions in the bbl
    bbl_all_instrs = {}

    tainted_instrs = {}
    instrs_to_include = {}

    pc = bbl.start
    for inst in bbl:
        tokens, inst_size = inst

        inst = Instruction()
        curr_pc = pc
        inst.setAddress(pc)
        inst_bytes = bv.read(pc, inst_size)
        inst.setOpcode(inst_bytes)
        bbl_all_instrs[pc] = inst

        pc += inst_size  

        ctx.processing(inst)
        for se in inst.getSymbolicExpressions():
            se.setComment(str(inst))

        # if pc == 0x416e07:
        #     print(inst.getLoadAccess())
        #     print(inst.getOperands())

        #     print('abc')

        # if inst.
        
        # if pc == 0x00416e62:
        #     # inst.setReadRegister
        #     read_registers = inst.getReadRegisters()
        #     if inst.isMemoryRead() and len(read_registers) > 0:
        #         ecxExpr = read_registers[0]
        #         print(ecxExpr[0])
        #         # print(ecxExpr[0].getName())
        #         print('===============')

        # if pc == 0x0040114c:
        #     print(inst.getReadRegisters())

        # print(hex(pc))

        # skip call and jmp instructions
        if inst_bytes[0] in ['\xe8', '\xe9']:
            instrs_to_include[inst.getAddress()] = inst.getDisassembly()
            continue

        if is_inst_writes_reg(inst, 'ebp'):
            instrs_to_include[inst.getAddress()] = inst.getDisassembly()
        
        if is_inst_writes_reg(inst, 'esp'):
            instrs_to_include[inst.getAddress()] = inst.getDisassembly()

        # related_regs = [REG.X86.EAX, REG.X86.EBX, REG.X86.ECX, REG.X86.EDX]
        if inst.isMemoryWrite():
            read_registers = inst.getReadRegisters()
            # print(read_registers)
            if type(read_registers) == tuple:
                read_registers = [read_registers]

            if len(read_registers) > 0:
                print(hex(inst.getAddress()))
                for read_reg, ast in read_registers:
                    # print(read_reg.getName())
                    if read_reg.getName() == 'eax':
                        # print('here')
                        instrs_to_include[inst.getAddress()] = inst.getDisassembly()
                        result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.EAX])
                        tainted_instrs = merge_dict(tainted_instrs, result)

                    if read_reg.getName() == 'ebx':
                        instrs_to_include[inst.getAddress()] = inst.getDisassembly()
                        result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.EBX])
                        tainted_instrs = merge_dict(tainted_instrs, result)

                    if read_reg.getName() == 'ecx':
                        instrs_to_include[inst.getAddress()] = inst.getDisassembly()
                        result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.ECX])
                        tainted_instrs = merge_dict(tainted_instrs, result)

                    if read_reg.getName() == 'edx':
                        instrs_to_include[inst.getAddress()] = inst.getDisassembly()
                        result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.EDX])
                        tainted_instrs = merge_dict(tainted_instrs, result)

                    print('===============')


        if inst.isBranch():
            if inst.getDisassembly().startswith('jne') or \
                inst.getDisassembly().startswith('je') or \
                inst.getDisassembly().startswith('jz') or \
                inst.getDisassembly().startswith('jnz'):
                
                instrs_to_include[inst.getAddress()] = inst.getDisassembly()
                result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.ZF])
                tainted_instrs = merge_dict(tainted_instrs, result)


            if inst.getDisassembly().startswith('jb') or \
                inst.getDisassembly().startswith('jnae') or \
                inst.getDisassembly().startswith('jnb') or \
                inst.getDisassembly().startswith('jae'):

                instrs_to_include[inst.getAddress()] = inst.getDisassembly()
                result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.CF])
                tainted_instrs = merge_dict(tainted_instrs, result)


            if inst.getDisassembly().startswith('jl') or \
                inst.getDisassembly().startswith('jge') or \
                inst.getDisassembly().startswith('jnl') or \
                inst.getDisassembly().startswith('jg') or \
                inst.getDisassembly().startswith('jnle'):

                instrs_to_include[inst.getAddress()] = inst.getDisassembly()
                result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.SF])
                tainted_instrs = merge_dict(tainted_instrs, result)
                result = slice_expr(ctx, ctx.getSymbolicRegisters()[REG.X86.OF])
                tainted_instrs = merge_dict(tainted_instrs, result)

    # print_slice_result(tainted_instrs)
    newly_tainted_instrs = tainted_instrs.copy()

    if len(tainted_instrs) > 0:
        while True:
            instrs_need_further_taint = \
                find_instrs_need_further_taint(bv, bbl, newly_tainted_instrs, bbl_all_instrs)
            
            print('there are %d instructions that need further tainting' \
                                % len(instrs_need_further_taint))
            for addr in instrs_need_further_taint.keys():
                print(hex(addr))

            if len(instrs_need_further_taint) == 0:
                break
            
            newly_tainted_instrs = further_taint_bbl_instrs(bv, bbl, instrs_need_further_taint)
            # print_slice_result(newly_tainted_instrs)

            tainted_instrs = merge_dict(tainted_instrs, newly_tainted_instrs)

    # print_slice_result(tainted_instrs)
    # print('===============================')
    # print_slice_result(instrs_to_include)
    # print('===============================')
    
    # print_slice_result(instrs_to_include)
    instrs_to_include = merge_dict(instrs_to_include, tainted_instrs)
    print_slice_result(instrs_to_include)

    return instrs_to_include


def highlight_included_instrs(bv, bbl, instrs_to_include):
    for addr in instrs_to_include.keys():
        bv.set_comment_at(addr, '1')

def nop_excluded_instrs(bv, bbl, instrs_to_include):

    print('inside nop_excluded_instrs()')
    included_addrs = instrs_to_include.keys()
    
    nop_started = False
    # nop_len = 0
    nop_start_addr = 0

    for inst in bbl.get_disassembly_text():
        addr = inst.address
        if not addr in included_addrs:
            bv.convert_to_nop(addr)
            if not nop_started:
                nop_started = True
                nop_start_addr = addr
            # accumulate the length
            # nop_len += bv.get_instruction_length(addr)
        else:
            # a sequence of nop comes to an end
            if nop_started:
                                
                # a jmp is 5 bytes long
                if addr - nop_start_addr >= 5:
                    dis = 'jmp 0x%x' % addr
                    inst_bytes = arch.assemble(dis, nop_start_addr)
                    bv.write(nop_start_addr, inst_bytes)
                    print('0x%x: %s' % (nop_start_addr, dis))
                
                nop_started = False
                # nop_len = 0
                nop_start_addr = 0

def solve_opaque_predicate(bv, func):
    
    print('solve_opaque_predicate()')

    for bbl in func.basic_blocks:

        # print('processing basic block at addr: 0x%x' % bbl.start)

        # jne to self
        if bbl.instruction_count == 1:
            instr = bbl.get_disassembly_text()[0]
            if instr.tokens[0].text.startswith('jne'):
                bv.never_branch(instr.address)  
            continue

        instrs = bbl.get_disassembly_text()

        try:
            instr1, instr2 = instrs[-2 :]
        except:
            print('error at: 0x%x' % bbl.start)
            # break

        # print(instr1, instr2)

        if is_opaque_predicate(instr1):
            # print('found opaque predicate')
            if should_patch_to_always_branch(instr2):
                log_info('always branch at: 0x%x' % instr2.address)
                bv.always_branch(instr2.address)
            elif should_patch_to_never_branch(instr2):
                log_info('never branch at: 0x%x' % instr2.address)
                bv.never_branch(instr2.address)   

def solve_push_jmp(bv, func):

    print('solve_push_jmp()')
    for bbl in func.basic_blocks:
        if bbl.instruction_count < 5:
            continue
        
        disassembly_text = bbl.get_disassembly_text()
        if str(disassembly_text[-5]).startswith('call    $+5') and \
            str(disassembly_text[-4]).startswith('pop     eax') and \
            str(disassembly_text[-3]).startswith('add     eax, 0xa') and \
            str(disassembly_text[-2]).startswith('push    eax') and \
            str(disassembly_text[-1]).startswith('jmp'):

            patch_addr = disassembly_text[-5].address
            print('push_jump at: 0x%x' % patch_addr)

            jmp_addr = disassembly_text[-1].address
            callee_offset_bytes = bv.read(jmp_addr + 1, 4)
            caller_offset = struct.unpack('<i', callee_offset_bytes)[0]
            callee_addr = jmp_addr + caller_offset + 5

            dis = 'call 0x%x' % callee_addr
            inst_bytes = arch.assemble(dis, patch_addr)
            bv.write(patch_addr, inst_bytes)
            
            # this sequence is 15 byte long
            return_addr = patch_addr + 15
            jmp_addr = patch_addr + len(inst_bytes)
            dis_jmp = 'jmp 0x%x' % return_addr

            inst_bytes = arch.assemble(dis_jmp, jmp_addr)
            bv.write(jmp_addr, inst_bytes)

def solve_load_ops(bv, ops):
    # if not ops[-1][0] == 'sub':
    #     print('warning：sequence does not end with sub')
    # if not (5 <= len(ops) <= 8):
    #     print('warning: there are %d operations in the sequence' % len(ops))
    
    val = 0
    for opcode, operand in ops:
        if opcode == 'mov':
            addr = int(operand, 16)
            # br = BinaryReader(bv, Endianness.LittleEndian)
            # val = br.read32()
            val_bytes = bv.read(addr, 4)
            val = struct.unpack('<I', val_bytes)[0]
            print(hex(val))
        elif opcode == 'add':
            val = (val + int(operand, 16)) & 0xffffffff
        elif opcode == 'sub':
            val = (val - int(operand, 16)) % (1 << 32)
        elif opcode == 'xor':
            val = val ^ int(operand, 16)
        elif opcode == 'shl':
            val = val << int(operand, 16)
            val &= 0xffffffff
        elif opcode == 'shr':
            val = val >> int(operand, 16)
        else:
            print('unknown operation: %s' % opcode)

    return val

def is_valid_op_sequence(ops):
    if not ops[-1][0] == 'sub':
        # print('warning：sequence does not end with sub')
        return False
    if not (5 <= len(ops) <= 8):
        # print('warning: there are %d operations in the sequence' % len(ops))
        return False

    return True

def solve_load_for_reg_bbl(bv, bbl, reg):
    pass

def solve_load_bbl(bv, bbl):
    
    for reg in ['eax', 'ebx', 'ecx', 'edx']:

        sequence_found = False
        sequence_start = 0
        sequence_instr_count = 0
        sequence_byte_length = 0
        ops = []

        for inst in bbl.get_disassembly_text():
            
            if not sequence_found:
                # print(str(inst))
                # print(r'mov\s*%s, dword \[data_(.*)\]' % reg)
                found = re.findall(r'mov\s*%s, dword \[data_(.*)\]' % reg, str(inst))
                if len(found) >= 1:
                    # print('found')
                    sequence_found = True
                    sequence_start = inst.address
                    ops.append(('mov', found[0]))
                    sequence_instr_count = 1
                    sequence_byte_length = bv.get_instruction_length(inst.address)

            else:
                matched = re.findall(r'(add|sub|shl|shr|xor)\s*%s, 0x(.*)' % reg, str(inst))
                if len(matched) >= 1:
                    ops.append((matched[0][0], matched[0][1]))
                    sequence_instr_count += 1
                    sequence_byte_length += bv.get_instruction_length(inst.address)
                
                else:
                    # we reached an end of a sequence
                    if is_valid_op_sequence(ops):

                        val = solve_load_ops(bv, ops)
                        dis = 'mov %s, 0x%x' % (reg, val)
                        inst_bytes = arch.assemble(dis, sequence_start)
                        mov_instr_len = len(inst_bytes)
                        bv.write(sequence_start, inst_bytes)
                        print('0x%x: %s' % (sequence_start, dis))
        
                        dis = 'jmp 0x%x' % (sequence_start + sequence_byte_length)
                        inst_bytes = arch.assemble(dis, sequence_start + mov_instr_len)
                        bv.write(sequence_start + mov_instr_len, inst_bytes)

                    # reset 
                    sequence_found = False
                    sequence_start = 0
                    sequence_instr_count = 0
                    sequence_byte_length = 0
                    ops = []

                # print(sequence_byte_length)


def solve_load(bv, func):

    print('solve_load()')
    for bbl in func.basic_blocks:
        solve_load_bbl(bv, bbl)
    

def deobfuscate_function(bv, addr):

    func = bv.get_functions_containing(addr)[0]
    print('there are %d basic blocks in func %s' % 
        (len(func.basic_blocks), func.name))

    bv.begin_undo_actions()

    solve_opaque_predicate(bv, func)

    solve_push_jmp(bv, func)

    # solve_load(bv, func)

    bv.commit_undo_actions()

    
def simplify_func(bv, addr):

    func = bv.get_functions_containing(addr)[0]
    print('there are %d basic blocks in func %s' % 
        (len(func.basic_blocks), func.name))

    bv.begin_undo_actions()

    simplify_bbls(bv, func)

    solve_load(bv, func)

    bv.commit_undo_actions()

def simplify_bbls(bv, func):

    for bbl in func:
        # bbl = bv.get_basic_blocks_at(addr)[0]
        instrs_to_include = simplify_bbl(bv, bbl)

        # bv.begin_undo_actions()

        # highlight_included_instrs(bv, bbl, instrs_to_include)
        nop_excluded_instrs(bv, bbl, instrs_to_include)

        # bv.commit_undo_actions()

def simplify_bbl_handler(bv, addr):

    bbl = bv.get_basic_blocks_at(addr)[0]

    instrs_to_include = simplify_bbl(bv, bbl)

    bv.begin_undo_actions()

    nop_excluded_instrs(bv, bbl, instrs_to_include)

    solve_load_bbl(bv, bbl)
    
    bv.commit_undo_actions()
import gdb
import struct

def get_reg_value(response):
    response = response.split()[2]
    value = int(response, 16)
    return value
    
class Solve(gdb.Command):
    def __init__(self):
        # This registers our class as "solve"
        super(Solve, self).__init__("solve", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        # When we call "solve" from gdb, this is the method
        # that will be called.
        print("Hello from solve 123!")

        dummy_input = open('input.txt', 'wb')
        dummy_input.write(b'1' * 0x50)
        dummy_input.close()

        solution = bytes()

        inferiors = gdb.inferiors()
        inferior = inferiors[0]
        gdb.execute('del')
        gdb.execute('file crackme.elf')
        gdb.execute('set breakpoint pending on')
        gdb.execute('b __libc_start_main')
        gdb.execute('r < input.txt')
        response = gdb.execute('p/x $rdi', to_string = True)
        main_addr = get_reg_value(response)
        main_addr_raw = 0x1229
        print(main_addr)
        base = main_addr - main_addr_raw

        gdb.execute('b *%d' % (base + 0x1399))
        gdb.execute('c')

        response = gdb.execute('p/x $rax', to_string = True)
        input_addr = get_reg_value(response)
        print('input_addr', hex(input_addr))
        
        i = 0
        while True:
            try:
                gdb.execute('del')
                gdb.execute('rwatch *%d' % (input_addr + i * 4))
                gdb.execute('c')

                response = gdb.execute('p/x $edi', to_string = True)
                checksum = get_reg_value(response)
                print('checksum', hex(checksum))
                solution += struct.pack('<I', checksum)
                
                gdb.execute('set $rsi = %d' % checksum)
                i += 1
            except:
                break

        print('=' * 50)
        print('the flag is:')
        print(solution)
        print('len:', len(solution))

        output = open('solution.txt', 'wb')
        output.write(solution)
        output.close()


# This registers our class to the gdb runtime at "source" time.
Solve()

# usage:
# 1. run gdb
# 2. inside gdb, run `source gdb_solve.py`
# 3. inside gdb, run `solve`
# 4. after it runs, it should print the solution and also write it to solution.txt
# 5. verify it by `cat solution.txt | ./crackme.elf`
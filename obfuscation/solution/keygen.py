import struct 
def crc32(s, init_val = 0, final_xor = 0):

    poly = 0xedb88320
    crc = init_val
    for c in s:
        if type(c) == str:
            asc = ord(c)
        else:
            asc = c

        asc ^= 0xffffffff
        crc ^= asc

        for _ in range(8):
            eax = crc & 1
            var_c_1 = (-eax) % 0xffffffff

            var_8 = crc >> 1
            var_c_1 &= poly

            crc = var_8 ^ var_c_1

        crc ^= 0xffffffff

    crc ^= final_xor   
    return crc  

def transform_back(buffer):

    rngs_vals = [
        0x10D88067, 
        0xBC16D3D5, 
        0xE7039A64, 
        0x39EC8A6D, 
        0xFF09B4BF, 
        0xF828DB76, 
        0x8BE40C8E, 
        0xF7AA583E, 
        0x60858E23, 
        0xE487F5A3, 
        0x39A57B89, 
        0xB006573E, 
        0x79609807, 
        0x620AD108, 
        0x5CD86398, 
        0x6CA94B51
    ]
    var_0x8c = 0

    ints = struct.unpack('<' + 'I' * 16, buffer)
    restored_ints = []

    for i in range(16):
        restored_int = ints[i] ^ rngs_vals[i] ^ var_0x8c
        restored_ints.append(restored_int)
        var_0x8c = restored_int

    return restored_ints

def main():

    name = 'jeff'
    sn = 0x12348765
    feature = 0x123
    expire_year = 0x2981
    expire_month = 0x34
    expire_date = 0x12

    buffer = name + '\x00' * (32 - len(name))
    buffer += struct.pack('<I', sn)
    buffer += struct.pack('<I', feature)
    buffer += struct.pack('<H', expire_year)
    buffer += struct.pack('<B', expire_month)
    buffer += struct.pack('<B', expire_date)

    buffer += '\x00' * 16

    # buffer = [
	# 0x77, 0x77, 0x77, 0x2e, 0x63, 0x72, 0x61, 0x63, 0x6b, 0x6d, 0x65, 0x73, 0x2e, 0x64, 0x65, 0x00,
	# 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	# 0x78, 0x56, 0x34, 0x12, 0x0f, 0xff, 0x00, 0x00, 0x12, 0x20, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
	# 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    # ]

    crc = crc32(buffer)

    buffer += struct.pack('<I', crc)

    print(buffer.encode('hex'))

    restored_int = transform_back(buffer)

    key = ''
    for val in restored_int:
        key += '%08x' % val
    
    print('key: ')
    print(key)


if __name__ == '__main__':
    main()

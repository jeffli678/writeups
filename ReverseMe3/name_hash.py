def rol(val, n):
    bin_str = bin(val)[2:]
    bin_str = '0' * (32 - len(bin_str)) + bin_str
    bin_str = bin_str[n : ] + bin_str[ : n]
    return int(bin_str, 2)

def calc_hash(name):
    val = 0
    for c in name:
        val += ord(c)
        val &= 0xffffffff
        val = rol(val, ord(c) & 31)
    return val

def main():
    hash_1 = calc_hash('LoadLibraryA')
    print(hex(hash_1))
    hash_2 = calc_hash('MessageBoxA')
    print(hex(hash_2))

main()
add_bits = {'0': 'add', '1': 'addi'}

nop_bits = {
    '00': 'c.nop',
    '01': 'c.or x8, x8',
    '10': 'c.andi x8, 0b011111',
    '11': 'c.and x8, x8',
}

# Big endian (RISC-V uses little-endian)
nop_opcodes = {
    'c.nop':  '0001',
    'c.or x8, x8': '8C41',
    'c.andi x8, 0b011111': '887D',
    'c.and x8, x8': '8C61',
}

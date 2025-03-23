add_bits = {"0": "add", "1": "addi"}

nop_bits = {
    "00": "c.nop",
    "01": "c.or x8, x8",
    "10": "c.andi x8, 0b011111",
    "11": "c.and x8, x8",
}

nop_opcodes = {
    "c.nop": "0100",
    "c.or x8, x8": "418c",
    "c.andi x8, 0b011111": "7d88",
    "c.and x8, x8": "618c",
}

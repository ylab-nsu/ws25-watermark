from dictionaries import add_bits, nop_bits, nop_opcodes

from riscv_watermark.watermarkers.interface import Watermarker

"""
Sample watermark example that just sets "add","addi", "c.add", "c.addi" to zeros  
"""


class ZerofierWatermarker(Watermarker):
    def __init__(self):
        super().__init__()

    def encode(self, filename, message):
        opcodes = ''
        bitstr = ''.join(format(x, 'b') for x in bytearray(message, 'utf-8'))
        bslen = len(bitstr)
        tracker = 0
        for i in super().disassembly(filename):
            if tracker < bslen: #the demo uses all available bits, but really it can be any amount, so we should modify until the message is coded
                if i.mnemonic == "addi" or i.mnemonic == "add" and list(i.op_str.split())[-1] in ['0', 'x0']:
                    if (bitstr[tracker] == '1' and i.mnemonic == 'add') or (bitstr[tracker] == '0' and i.mnemonic == 'addi'): #addi = 1; add = 0
                        opcodes += conv_func(i.mnemonic, i.op_str)
                    tracker += 1
                elif i.mnemonic == 'c.nop':
                    if bslen - tracker > 1:
                        new_mnem = nop_bits[str(bitstr[tracker : tracker + 2])]
                    else:
                        new_mnem = nop_bits[
                            str(bitstr[tracker : tracker + 1]) + '0'
                        ]
                    opcodes += nop_opcodes[new_mnem]
                    tracker += 2
                else:
                    opcodes += str(i)[str(i).find('[') + 1 : str(i).find(']')]
            else:
                opcodes += str(i)[str(i).find('[') + 1 : str(i).find(']')]
        return bytes(opcodes)

    def decode(self, filename):
        bitstr = ''
        nop_bits_revd = {j: i for i, j in nop_bits}
        for i in super().disassembly(filename):
            if i.mnemonic == 'addi':
                bitstr += '1'
            elif i.mnemonic == 'add':
                bitstr += '0'
            elif i.mnemonic in nop_bits_revd:
                bitstr += nop_bits_revd[i.mnemonic]

        return ''.join(
            chr(int(bitstr[i : i + 8], 2)) for i in range(0, len(bitstr), 8)
        )

    def get_nbits(self, filename):
        count = 0
        for i in super().disassembly(filename):
            if i.mnemonic == 'c.nop':
                count += 2
            elif i.mnemonic in ['c.addi', 'c.add']:
                count += 1
        return count


def conv_func(mnemonic, op_str):
    operands = op_str.split(', ')

    rd = operands[0][1:]
    rs1 = operands[1][1:]

    # rd и rs1 в 5 битные двоичных строках
    rd_bin = format(int(rd), '05b')
    rs1_bin = format(int(rs1), '05b')

    if mnemonic == 'addi':
        opcode = '0010011'
        machine_code = f'0000000{rs1_bin}000{rd_bin}{opcode}'

    elif mnemonic == 'add':
        opcode = '0110011'
        machine_code = f'0000000{rs1_bin}000{rd_bin}{opcode}'

    # Преобразуем полученный двоичный код в шестнадцатиричное представление
    hex_code = hex(int(machine_code, 2))

    return hex_code

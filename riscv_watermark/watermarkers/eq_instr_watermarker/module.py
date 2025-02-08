from riscv_watermark.watermarkers.interface import Watermarker
from riscv_watermark.watermarkers.eq_instr_watermarker.add_converter import \
    convert_add_addi
from riscv_watermark.watermarkers.eq_instr_watermarker.dictionaries import (
    nop_bits, nop_opcodes)

"""
Sample watermark example that just sets "add","addi", "c.add", "c.addi" to zeros  
"""

def decode_bitstring(bs):
    # Split the bit string into chunks of 8 bits (1 byte)
    n = 8
    chars = [bs[i:i+n] for i in range(0, len(bs), n)]
    
    # Convert each chunk into an ASCII character
    decoded_string = ''.join(chr(int(char, 2)) for char in chars)
    return decoded_string

def dict_rev(di):
    idi = {}
    for i, j in di.items():
        if j not in idi.keys():
            idi[j] = i
        else:
            idi[j] = [*idi[j]] if not isinstance(idi[j], str) else [idi[j]]
            idi[j].append(i)
            idi[j] = tuple(idi[j])
    return idi



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
    hex_code = hex(int(machine_code, 2))[2:]

    return hex_code

class ZerofierWatermarker(Watermarker):
    def __init__(self):
        super().__init__()

    def encode(self, filename: str, message: str):
        opcodes = ''
        bitstr = ''.join(format(ord(char), '08b') for char in message)
        bslen = len(bitstr)
        tracker = 0
        listing = super().disassembly(filename)
        for i in listing:
            orig_opcode = str(i)[str(i).find('[') + 1 : str(i).find(']')]
            if tracker < bslen: #the demo uses all available bits, but really it can be any amount, so we should modify until the message is coded
                if (i.mnemonic == "addi" or i.mnemonic == "add") and list(i.op_str.split())[-1] in ['0', 'x0', 'zero']:
                    if (bitstr[tracker] == '1' and i.mnemonic == 'add') or (bitstr[tracker] == '0' and i.mnemonic == 'addi'): #addi = 1; add = 0
                        opcode = orig_opcode
                        out = str(convert_add_addi(int.from_bytes(bytearray.fromhex(opcode))))
                        opcodes += out
                    tracker += 1
                elif i.mnemonic == 'c.nop':
                    if bslen - tracker > 1:
                        new_mnem = nop_bits[str(bitstr[tracker : tracker + 2])]
                    else:
                        new_mnem = nop_bits[
                            str(bitstr[tracker : tracker + 1]) + '0'
                        ]
                    opcode = nop_opcodes[new_mnem]
                    opcodes += opcode
                    tracker += 2
                else:
                    out = str(i)[str(i).find('[') + 1 : str(i).find(']')]
                    opcodes += out
            else:
                out = str(i)[str(i).find('[') + 1 : str(i).find(']')]
                opcodes += out
        return bytearray.fromhex(opcodes)

    def decode(self, filename):
        bitstr = ''
        nop_bits_revd = dict_rev(nop_bits)
        nop_opcodes_revd = dict_rev(nop_opcodes)
        listing = super().disassembly(filename)
        for i in listing:
            orig_opcode = str(i)[str(i).find('[') + 1 : str(i).find(']')]
            if i.mnemonic == 'addi' and list(i.op_str.split())[-1] in ['0', 'x0', 'zero']:
                bitstr += '1'
            elif i.mnemonic == 'add' and list(i.op_str.split())[-1] in ['0', 'x0', 'zero']:
                bitstr += '0'
            elif orig_opcode in list(nop_opcodes_revd.keys()):
                bitstr += nop_bits_revd[nop_opcodes_revd[orig_opcode]]
        bs = decode_bitstring(bitstr)
        return bs

    def get_nbits(self, filename):
        count = 0
        listing = super().disassembly(filename)
        for i in listing:
            if i.mnemonic == 'c.nop':
                count += 2
            elif i.mnemonic in ['addi', 'add'] and list(i.op_str.split())[-1] in ['0', 'x0', 'zero']:
                count += 1
        return count


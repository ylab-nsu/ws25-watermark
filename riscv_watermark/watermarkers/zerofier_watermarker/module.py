from riscv_watermark.watermarkers.interface import Watermarker
from dictionaries import nop_bits, add_bits, nop_opcodes, conv_func

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
                if i.mnemonic == "addi" or i.mnemonic == "add":
                    if bitstr[tracker] == '1' and i.mnemonic == 'add': #addi = 1; add = 0
                        conv_func(i.mnemonic, i.op_str)
                    tracker += 1
                elif i.mnemonic == 'c.nop':
                    if bslen - tracker > 1:
                        new_mnem = nop_bits[str(bitstr[tracker:tracker + 2])]
                    else:
                        new_mnem = nop_bits[str(bitstr[tracker:tracker + 1]) + '0']
                    opcodes += nop_opcodes[new_mnem]
                    tracker += 2
                else:
                    opcodes += str(i)[str(i).find('[') + 1:str(i).find(']')]
            else:
                opcodes += str(i)[str(i).find('[') + 1:str(i).find(']')]
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
                
        return ''.join(chr(int(bitstr[i:i+8], 2)) for i in range(0, len(bitstr), 8))

    def get_nbits(self, filename):
        count = 0
        for i in super().disassembly(filename):
            if i.mnemonic == 'c.nop':
                count += 2
            elif i.mnemonic in ['c.addi', 'c.add']:
                count += 1
        return count

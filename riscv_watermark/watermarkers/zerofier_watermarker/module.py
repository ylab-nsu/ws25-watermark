from riscv_watermark.watermarkers.interface import Watermarker

"""
Sample watermark example that just sets "add","addi", "c.add", "c.addi" to zeros  
"""
class ZerofierWatermarker(Watermarker):
    nop_bits = {'00':'c.nop', '01':'c.or a0, a0', '10':'andi a0, 0b', '11':'c.sub a0, r0'}
    def __init__(self):
        super().__init__()
    def encode(self, filename, message):
        opstr = b''
        bitstr = ''.join(format(x, 'b') for x in bytearray(message, 'utf-8'))
        tracker = 0
        for i in super().disassembly(filename):
            if i.mnemonic == "addi" or i.mnemonic == "add":
                if bitstr[tracker] == '1':
                    pass #change required
                tracker += 1
            elif i.mnemonic == 'c.nop':
                new_mnem = 
                tracker += 2
            else:
                opstr += i.op_str
        return opstr

    def decode(self, filename):
        pass

    def get_nbits(self, filename):
        count = 0
        for i in super().disassembly(filename):
            if i.mnemonic == 'c.nop':
                count += 2
            elif i.mnemonic in ['c.addi', 'c.add']:
                count += 1
        return count

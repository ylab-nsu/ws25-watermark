<<<<<<< HEAD
=======
from capstone import (
    CS_ARCH_RISCV,
    CS_MODE_RISCV32,
    CS_MODE_RISCV64,
    CS_MODE_RISCVC,
    Cs,
)

>>>>>>> 527360f6cfa02a27096cdfb4264472951e99a26e
from riscv_watermark.watermarkers.interface import Watermarker

"""
Sample watermark example that just sets "add","addi", "c.add", "c.addi" to zeros  
"""


class ZerofierWatermarker(Watermarker):
    nop_bits = {'00':'c.nop', '01':'c.or a0, a0', '10':'andi a0, 0b', '11':'c.sub a0, r0'}
    def __init__(self):
        super().__init__()
<<<<<<< HEAD
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
=======

    def encode(self, text_data, message):
        data = bytearray(text_data)
        md = Cs(
            CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV32 | CS_MODE_RISCVC
        )
        for i in md.disasm(data, 0x0):
            if i.mnemonic == 'addi' or i.mnemonic == 'add':
                # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                data[i.address : i.address + 4] = 0x00.to_bytes(
                    4, byteorder='little'
                )
            if i.mnemonic == 'c.add' or i.mnemonic == 'c.addi':
                # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                data[i.address : i.address + 2] = 0x00.to_bytes(
                    2, byteorder='little'
                )
        return bytes(data)
>>>>>>> 527360f6cfa02a27096cdfb4264472951e99a26e

    def decode(self, filename):
        pass

<<<<<<< HEAD
    def get_nbits(self, filename):
        count = 0
        for i in super().disassembly(filename):
            if i.mnemonic == 'c.nop':
                count += 2
            elif i.mnemonic in ['c.addi', 'c.add']:
                count += 1
        return count
=======
    def get_nbits(self, text_data):
        return 10000
>>>>>>> 527360f6cfa02a27096cdfb4264472951e99a26e

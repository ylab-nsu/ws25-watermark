from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV64, CS_MODE_RISCV32, CS_MODE_RISCVC

from riscv_watermark.watermarkers.interface import Watermarker

"""
Sample watermark example that just sets "add","addi", "c.add", "c.addi" to zeros  
"""
class ZerofierWatermarker(Watermarker):
    def __init__(self):
        super().__init__()
    def encode(self, text_data, message):
        data = bytearray(text_data)
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV32 | CS_MODE_RISCVC)
        for i in md.disasm(data, 0x0):
            if i.mnemonic == "addi" or i.mnemonic == "add":
                #print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                data[i.address:i.address + 4] = 0x00.to_bytes(4, byteorder='little')
            if i.mnemonic == "c.add" or i.mnemonic == "c.addi":
                #print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
                data[i.address:i.address + 2] = 0x00.to_bytes(2, byteorder='little')
        return bytes(data)

    def decode(self, text_data):
        pass

    def get_nbits(self, text_data):
        return 10000


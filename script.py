from elftools.elf.elffile import ELFFile
from capstone import *


def print_sep(st: str):
    print('=' * 20 + st + '=' * 20)

def section_dissas(section_name: str, filename: str):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        code = elf.get_section_by_name(section_name)
        ops = code.data()
        addr = code['sh_addr']
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV32 | CS_MODE_RISCVC)
        for i in md.disasm(ops, addr):
            print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\t{str(i)[str(i).find('[') + 1:str(i).find(']')]}')

filename = "hell"
sections = ['.text', '.patch']
for i in sections:
    print_sep(i)
    section_dissas(i, filename)

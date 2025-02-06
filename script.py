from capstone import *
from itertools import batched
from elftools.elf.elffile import ELFFile
import sys

def print_sep(st: str):
    print('=' * 20 + st + '=' * 20)

def pad(s):
    return f"{s:{'0'}>8}"

def section_dissas(section_name: str, filename: str, funcs: list):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        code = elf.get_section_by_name(section_name)
        ops = code.data()
        addr = code['sh_addr']
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV32 | CS_MODE_RISCVC)
        md.detail = True
        entry = elf.header.e_entry
        offs = entry - addr
        for i in md.disasm(ops[offs:], entry):
            if i.address in funcs:
                print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\t{str(i)[str(i).find('[') + 1:str(i).find(']')]}')


def get_symtab(filename: str) -> list:
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        # Check if the ELF file has a symbol table
        symtab = elf.get_section_by_name('.symtab')
        funcs = []
        # Iterate over the symbols in the symbol table
        print(f"Symbols in {elf_file_path}:")
        for symbol in symtab.iter_symbols():
            if symbol['st_size'] > 0 and symbol['st_info']['type'] == 'STT_FUNC':
                funcs.append(symbol)
            print(f"Name: {symbol.name}, Address: {hex(symbol['st_value'])}, Size: {symbol['st_size']} bytes, Type: {symbol['st_info']['type']}, Bind: {symbol['st_info']['bind']}")
        return funcs

if len(sys.argv) != 2:
    print("Usage: python3 disassemble.py <path_to_elf_binary>")
    sys.exit(1)

elf_file_path = sys.argv[1]
filename = elf_file_path
sections = ['.text']
funcs = get_symtab(filename)
print(len(funcs))
addrs = [i['st_value'] for i in funcs]
sizes = [i['st_size'] for i in funcs]
for i in sections:
    print_sep(i)
    section_dissas(i, filename, addrs)
f1 = open(filename, 'rb')
f = open('copy', 'wb')
read = f1.read()
f.write(read)
f1.close()
exc = {tuple(b'\x39\x71'):tuple(b'\x5d\x71')}
exc2 = {tuple(b'\x21\x61'):tuple(b'\x61\x61')}
print(exc)
print(exc2)
for i, j in zip(addrs, sizes):
    st = tuple(read[i:i+2])
    en = tuple(read[i + j - 1:i + j + 1])
    if st in exc.keys():
        st = exc[st]
        print(st, en)
    if en in exc2.keys():
        en = exc2[en]
        print(st, en)
    f.seek(i)
    f.write(bytes(st))
    f.seek(i + j - 1)
    f.write(bytes(en))
f.close()

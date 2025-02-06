import sys

from capstone import *
from elftools.elf.elffile import ELFFile


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

"""
Parses watermark methods to use
"""
def parse_methods(methods: str):
    return methods.split(',')


def decode_instruction(data, offset):
    instruction = int.from_bytes(data[offset:offset+2], byteorder='little')

    # переписать
    if (instruction & 0b11) != 0b11:
        return instruction, 2
    else:
        instruction = int.from_bytes(data[offset:offset+4], byteorder='little')
        return instruction, 4


def copy_file(input_file, output_file):
    with open(input_file, 'rb') as inp, open(output_file, 'wb') as out:
        out.write(inp.read())


def transform_addi_to_add(instruction):
    if (instruction & 0x7F) == 0x13:
        funct3 = (instruction >> 12) & 0x7
        imm = (instruction >> 20) & 0xFFF
        if funct3 == 0x0 and imm == 0x0:
            rd = (instruction >> 7) & 0x1F
            rs1 = (instruction >> 15) & 0x1F
            new_instruction = (0x00 << 25) | (0x00 << 20) | (rs1 << 15) | (0x0 << 12) | (rd << 7) | 0x33
            return new_instruction
    return instruction


def transform_add_to_addi(instruction):
    if (instruction & 0x7F) == 0x33:
        print("GOOOD")
        funct3 = (instruction >> 12) & 0x7
        funct7 = (instruction >> 24) & 0xFF
        rs2 = (instruction >> 20) & 0x1F
        rs1 = (instruction >> 15) & 0x1F
        if funct3 == 0x0 and funct7 == 0x00 and (rs2 == 0x0 or rs1 == 0x0):
            print("REALLY GOOOD")
            rd = (instruction >> 7) & 0x1F
            rs1 = (instruction >> 15) & 0x1F
            new_instruction = (0x00 << 20) | (rs1 << 15) | (0x0 << 12) | (rd << 7) | 0x13
            return new_instruction
    return instruction


def modify_text_section(section):
    data = bytearray(section.data())
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV32 | CS_MODE_RISCVC)
    for i in md.disasm(data,0x0):
        if i.mnemonic == "addi" or i.mnemonic == "add":
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            data[i.address:i.address+4] = 0x00.to_bytes(4, byteorder='little')
        if i.mnemonic == "c.add" or i.mnemonic == "c.addi":
            print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            data[i.address:i.address+2] = 0x00.to_bytes(2, byteorder='little')
    return bytes(data)


def modify_elf_file(input_filename:str, output_filename:str):
    input_file = open(input_filename, 'rb')
    input_elf = ELFFile(input_file)

    input_text_section = input_elf.get_section_by_name(".text")


    text_data = input_text_section.data()
    modified_text = modify_text_section(input_text_section)

    offset = input_text_section['sh_addr']
    size = input_text_section['sh_size']
    print(offset)
    print(size)

    input_file.close()

    input_file = open(input_filename, 'rb')
    output_file = open(output_filename,'wb')

    #new_data = input_file.read(offset) + modified_text
    output_file.write(input_file.read(offset))
    output_file.write(modified_text)

    input_file.seek(offset+size)

    # new_data += input_file.read()


    output_file.write(input_file.read())

    input_file.close()
    output_file.close()


"""
Replaces occurancies of "addi rd, rs1, 0" to "add rd, rs1, zero" and vice versa
Currently does not work properly
"""



def usage():
    print("Usage: python script.py <input_elf_file>")
    sys.exit(1)



if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()

    filename = sys.argv[1]
    print(f"Modifying {filename}")
    copy_file(filename, f"{filename}.patched")
    modify_elf_file(filename, f"{filename}.patched")

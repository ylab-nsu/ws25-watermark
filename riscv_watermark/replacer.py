import sys
from elftools.elf.elffile import ELFFile

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

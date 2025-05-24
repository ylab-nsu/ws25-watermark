from watermark_framework.architecture import Architecture
from watermark_framework.watermarkers.interface import Watermarker
from watermark_framework.io import TextSection
from .add_converter import convert_add_addi
from .dictionaries import nop_bits, nop_opcodes
from typing import Dict

class EquivalentInstructionWatermarker(Watermarker):
    SUPPORTED_ARCHS = {Architecture.RISCV}
    METHOD_NAME = "EquivalentInstructionWatermarker"

    def __init__(self):
        super().__init__()
        self.nop_bits: Dict[str, str] = nop_bits
        self.nop_opcodes: Dict[str, str] = nop_opcodes
        self.opcode_to_bits: Dict[str, str] = {
            self.nop_opcodes[mnem]: bits for bits, mnem in self.nop_bits.items()
        }

    def encode(self, section: TextSection, message: bytes) -> bytes:
        bitstr = ''.join(format(byte, '08b') for byte in message)
        bslen = len(bitstr)
        tracker = 0
        new_data = bytearray(section.data)

        for i in section.insns:
            offset = i.address - section.vma
            if tracker < bslen:
                operands = i.op_str.split(", ")
                if (i.mnemonic == "addi" and operands[-1] == "0") or \
                   (i.mnemonic == "add" and operands[-1] in ["x0", "zero"]):
                    b = bitstr[tracker]
                    if (b == "1" and i.mnemonic == "add") or (b == "0" and i.mnemonic == "addi"):
                        orig_opcode = int.from_bytes(i.bytes, 'little')
                        new_opcode = convert_add_addi(orig_opcode)
                        new_data[offset:offset + 4] = new_opcode
                    # Else, keep the original opcode as it already matches the bit
                    tracker += 1
                elif i.mnemonic == "c.nop":
                    if tracker + 1 < bslen:
                        bb = bitstr[tracker:tracker + 2]
                        tracker += 2
                    else:
                        bb = bitstr[tracker:] + "0"
                        tracker += 1
                    mnem = self.nop_bits[bb]
                    opcode_bytes = bytes.fromhex(self.nop_opcodes[mnem])
                    new_data[offset:offset + 2] = opcode_bytes
            # Else, keep original opcode if message bits are exhausted

        return bytes(new_data)

    def decode(self, section: TextSection) -> bytes:
        bitstr = ""
        for i in section.insns:
            operands = i.op_str.split(", ")
            if i.mnemonic == "addi" and operands[-1] == "0":
                bitstr += "1"
            elif i.mnemonic == "add" and operands[-1] in ["x0", "zero"]:
                bitstr += "0"
            elif i.bytes.hex() in self.opcode_to_bits:
                bitstr += self.opcode_to_bits[i.bytes.hex()]

        # Convert bitstring to bytes, ignoring incomplete bytes
        message = bytearray()
        for i in range(0, len(bitstr), 8):
            byte_str = bitstr[i:i + 8]
            if len(byte_str) < 8:
                break
            message.append(int(byte_str, 2))
        return bytes(message)

    def get_nbits(self, section: TextSection) -> int:
        count = 0
        for i in section.insns:
            operands = i.op_str.split(", ")
            if (i.mnemonic == "addi" and operands[-1] == "0") or \
               (i.mnemonic == "add" and operands[-1] in ["x0", "zero"]):
                count += 1
            elif i.mnemonic == "c.nop":
                count += 2
        return count

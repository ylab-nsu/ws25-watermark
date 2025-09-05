import copy

from capstone import Cs, CsInsn
from capstone.x86_const import X86_GRP_JUMP, X86_GRP_CALL, X86_GRP_RET
from keystone import Ks

from watermark_framework.architecture import Architecture
from watermark_framework.io import TextSection
from watermark_framework.watermarkers.interface import Watermarker
from .x86_pairs import EQUIVALENCE_GROUPS


class EquivalentInstructionWatermarkerX86(Watermarker):
    """
    Watermarker for x86_64 using equivalent instruction substitution.
    """

    METHOD_NAME = "EQ_INSTR_X86"
    SUPPORTED_ARCHS = {Architecture.X86_64}
    REQUIRES_DETAILED = True

    def __init__(self):
        super().__init__()
        self._enriched_groups = self._precompute_flag_data()

    def _precompute_flag_data(self) -> list[dict]:
        arch = Architecture.X86_64
        if not (arch.ks_arch and arch.ks_mode and arch.capstone_arch and arch.capstone_mode):
            return []

        ks = Ks(arch.ks_arch, arch.ks_mode)
        cs = Cs(arch.capstone_arch, arch.capstone_mode)
        cs.detail = True

        enriched_groups = copy.deepcopy(EQUIVALENCE_GROUPS)

        for group in enriched_groups:
            group["bit_width"] = (len(group["representatives"]) - 1).bit_length() if group.get("representatives") else 0
            group["flags_map"] = {}
            for member in group.get("representatives", []):
                try:
                    encoding, _ = ks.asm(member["asm"])
                    if encoding is not None:
                        insn = next(cs.disasm(bytes(bytearray(encoding)), 0))
                        group["flags_map"][member["bit"]] = insn.eflags
                    else:
                        group["flags_map"][member["bit"]] = 0
                except Exception:
                    group["flags_map"][member["bit"]] = 0

        return sorted(enriched_groups, key=lambda g: g["bit_width"], reverse=True)


    def _is_end_of_block(self, insn: CsInsn) -> bool:
        return insn.group(X86_GRP_JUMP) or insn.group(X86_GRP_CALL) or insn.group(X86_GRP_RET)

    def _analyze_safety(self, insn: CsInsn, group: dict, target_bit: str, all_insns: list[CsInsn], insn_idx: int) -> bool:
        current_bit = group["get_bit"](insn)
        if current_bit == target_bit:
            return True

        flags_map = group.get("flags_map", {})
        flags_current = flags_map.get(current_bit, 0)
        flags_target = flags_map.get(target_bit, 0)

        dangerous_flags = flags_current ^ flags_target
        if dangerous_flags == 0:
            return True

        for next_insn in all_insns[insn_idx + 1:]:
            if self._is_end_of_block(next_insn): return True
            if next_insn.eflags & dangerous_flags:
                dangerous_flags &= ~next_insn.eflags
                if dangerous_flags == 0: return True
        return False

    def get_nbits(self, section: TextSection) -> int:
        total_bits = 0
        for insn in section.insns:
            for group in self._enriched_groups:
                if group["is_candidate"](insn):
                    total_bits += group["bit_width"]
                    break
        return total_bits

    def encode(self, section: TextSection, message: bytes) -> bytes:
        if not section.ks: return section.data

        bitstr = "".join(format(byte, "08b") for byte in message)
        bit_idx = 0
        new_data = bytearray(section.data)
        all_insns = section.insns

        for i, insn in enumerate(all_insns):
            best_action = None
            for group in self._enriched_groups:
                if group["is_candidate"](insn):
                    width = group["bit_width"]
                    if bit_idx >= len(bitstr):
                        target_bits = '0' * width
                    else:
                        if bit_idx + width > len(bitstr):
                            continue
                        desired_bits = bitstr[bit_idx : bit_idx + width]
                        if not any(m["bit"] == desired_bits for m in group["representatives"]):
                            continue
                        target_bits = desired_bits

                    if self._analyze_safety(insn, group, target_bits, all_insns, i):
                        best_action = {
                            "group": group,
                            "target_bits": target_bits,
                            "width": width,
                        }
                        break

            if best_action:
                current_bits = best_action["group"]["get_bit"](insn)
                target_bits = best_action["target_bits"]

                if current_bits != target_bits:
                    asm_string = best_action["group"]["get_asm_for_bit"](insn, target_bits)
                    try:
                        new_bytes, _ = section.ks.asm(asm_string, insn.address)
                        if new_bytes is not None and len(new_bytes) == len(insn.bytes):
                            offset = insn.address - section.vma
                            new_data[offset : offset + len(new_bytes)] = new_bytes
                        else:
                            return bytes(new_data)
                    except Exception:
                        return bytes(new_data)

                if bit_idx < len(bitstr):
                    bit_idx += best_action["width"]

        return bytes(new_data)

    def decode(self, section: TextSection) -> bytes:
        decoded_bitstr = ""
        for insn in section.insns:
            for group in self._enriched_groups:
                if group["is_candidate"](insn):
                    decoded_bitstr += group["get_bit"](insn)
                    break

        message = bytearray()
        for i in range(0, len(decoded_bitstr), 8):
            byte_str = decoded_bitstr[i : i + 8]
            if len(byte_str) == 8:
                message.append(int(byte_str, 2))

        return bytes(message)
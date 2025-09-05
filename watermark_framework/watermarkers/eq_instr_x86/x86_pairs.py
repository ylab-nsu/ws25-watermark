from capstone import CsInsn
from capstone.x86_const import X86_OP_IMM, X86_OP_REG

# ==============================================================================
# Helper functions
# ==============================================================================

def _get_asm_for_zeroing_op(insn: CsInsn, bit: str) -> str:
    """Return the assembly string for the desired bit ('sub' or 'xor')."""
    target_mnemonic = "sub" if bit == "0" else "xor"
    return f"{target_mnemonic} {insn.op_str}"

def _get_asm_for_positive_arith(insn: CsInsn, bit: str) -> str:
    """Transforms between `add reg, K` and `sub reg, -K`."""
    reg_name = insn.reg_name(insn.operands[0].reg)
    imm_val = abs(insn.operands[1].imm)

    if bit == "0":
        return f"add {reg_name}, {imm_val}"
    else:
        return f"sub {reg_name}, {-imm_val}"

def _get_asm_for_negative_arith(insn: CsInsn, bit: str) -> str:
    """Transforms between `sub reg, K` and `add reg, -K`."""
    reg_name = insn.reg_name(insn.operands[0].reg)
    imm_val = abs(insn.operands[1].imm)

    if bit == "0":
        return f"sub {reg_name}, {imm_val}"
    else:
        return f"add {reg_name}, {-imm_val}"

# ==============================================================================
# The Main Equivalence List
# ==============================================================================

EQUIVALENCE_GROUPS = [
    {
        "name": "ZEROING_REGISTER",
        "is_candidate": lambda insn: (
            insn.mnemonic in ("sub", "xor") and
            len(insn.operands) == 2 and
            insn.operands[0].type == X86_OP_REG and
            insn.operands[0].reg == insn.operands[1].reg
        ),
        "get_bit": lambda insn: "0" if insn.mnemonic == "sub" else "1",
        "get_asm_for_bit": _get_asm_for_zeroing_op,
        "representatives": [
            {"bit": "0", "asm": "sub rax, rax"},
            {"bit": "1", "asm": "xor rax, rax"}
        ]
    },
    {
        "name": "POSITIVE_ARITHMETIC",
        "is_candidate": lambda insn: (
            len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM and
            ((insn.mnemonic == "add" and insn.operands[1].imm > 0) or
             (insn.mnemonic == "sub" and insn.operands[1].imm < 0))
        ),
        "get_bit": lambda insn: "0" if insn.mnemonic == "add" else "1",
        "get_asm_for_bit": _get_asm_for_positive_arith,
        "representatives": [{"bit": "0", "asm": "add rax, 50"}, {"bit": "1", "asm": "sub rax, -50"}]
    },
    {
        "name": "NEGATIVE_ARITHMETIC",
        "is_candidate": lambda insn: (
            len(insn.operands) == 2 and insn.operands[1].type == X86_OP_IMM and
            ((insn.mnemonic == "sub" and insn.operands[1].imm > 0) or
             (insn.mnemonic == "add" and insn.operands[1].imm < 0))
        ),
        "get_bit": lambda insn: "0" if insn.mnemonic == "sub" else "1",
        "get_asm_for_bit": _get_asm_for_negative_arith,
        "representatives": [{"bit": "0", "asm": "sub rax, 50"}, {"bit": "1", "asm": "add rax, -50"}]
    },
    {
        "name": "INC_ADD_1",
        "is_candidate": lambda insn: (
            (insn.mnemonic == "inc" and len(insn.operands) == 1) or
            (insn.mnemonic == "add" and len(insn.operands) == 2 and getattr(insn.operands[1], 'imm', None) == 1)
        ),
        "get_bit": lambda insn: "0" if insn.mnemonic == "inc" else "1",
        "get_asm_for_bit": lambda insn, bit: (
            f"inc {insn.op_str.split(',')[0]}" if bit == "0" else f"add {insn.op_str.split(',')[0]}, 1"
        ),
        "representatives": [
            {"bit": "0", "asm": "inc rax"},
            {"bit": "1", "asm": "add rax, 1"}
        ]
    },
    {
        "name": "DEC_SUB_1",
        "is_candidate": lambda insn: (
            (insn.mnemonic == "dec" and len(insn.operands) == 1) or
            (insn.mnemonic == "sub" and len(insn.operands) == 2 and getattr(insn.operands[1], 'imm', None) == 1)
        ),
        "get_bit": lambda insn: "0" if insn.mnemonic == "dec" else "1",
        "get_asm_for_bit": lambda insn, bit: (
            f"dec {insn.op_str.split(',')[0]}" if bit == "0" else f"sub {insn.op_str.split(',')[0]}, 1"
        ),
        "representatives": [
            {"bit": "0", "asm": "dec rax"},
            {"bit": "1", "asm": "sub rax, 1"}
        ]
    },
    {
        "name": "TEST_VS_AND_SELF",
        "is_candidate": lambda insn: (
            insn.mnemonic in ("test", "and") and
            len(insn.operands) == 2 and
            insn.operands[0].type == X86_OP_REG and
            insn.operands[0].reg == insn.operands[1].reg
        ),
        "get_bit": lambda insn: "0" if insn.mnemonic == "test" else "1",
        "get_asm_for_bit": lambda insn, bit: (
            f"{'test' if bit == '0' else 'and'} {insn.op_str}"
        ),
        "representatives": [
            {"bit": "0", "asm": "test rax, rax"},
            {"bit": "1", "asm": "and rax, rax"}
        ]
    },
]

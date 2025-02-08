def convert_add_addi(instr):
    """Конвертирует ADDI rd, rs1, 0 в ADD rd, rs1, x0 и наоборот."""
    is_add, add_data = is_addx0(instr)
    if is_add:
        return get_addi0(add_data)

    is_addi, addi_data = is_addi0(instr)
    if is_addi:
        return get_addx0(addi_data)

    return None  # Если инструкция не подходит под условия


def is_addx0(instr):
    """Проверяет, является ли инструкция `add rd, rs1, rs2` с rs1 или rs2 = x0."""
    opcode1 = instr & 0x7F  # opcode1 (7 бит, младшие биты)
    rd = (instr >> 7) & 0x1F  # rd (5 бит)
    opcode2 = (instr >> 12) & 0x7  # opcode2 (3 бита)
    rs1 = (instr >> 15) & 0x1F  # rs1 (5 бит)
    rs2 = (instr >> 20) & 0x1F  # rs2 (5 бит)
    opcode3 = (instr >> 25) & 0x7F  # opcode3 (7 бит)

    # Проверяем опкоды (обычный ADD)
    if opcode1 == 0b0110011 and opcode2 == 0b000 and opcode3 == 0b0000000:
        if rs1 == 0:
            return True, (rd, rs2)
        elif rs2 == 0:
            return True, (rd, rs1)

    return False, None


def is_addi0(instr):
    """Проверяет, является ли инструкция `addi rd, rs1, 0`."""
    opcode1 = instr & 0x7F  # opcode1 (7 бит)
    rd = (instr >> 7) & 0x1F  # rd (5 бит)
    opcode2 = (instr >> 12) & 0x7  # opcode2 (3 бита)
    rs1 = (instr >> 15) & 0x1F  # rs1 (5 бит)
    imm = (instr >> 20) & 0xFFF  # imm (12 бит)

    # Проверяем опкоды (ADDI с imm = 0)
    if opcode1 == 0b0010011 and opcode2 == 0b000 and imm == 0:
        return True, (rd, rs1)

    return False, None


def get_addx0(data):
    """Генерирует байтовое представление инструкции ADD rd, rs1, x0."""
    rd, rs1 = data
    opcode1 = 0b0110011
    opcode2 = 0b000
    rs2 = 0
    opcode3 = 0b0000000

    instr = (
        (opcode3 << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (opcode2 << 12)
        | (rd << 7)
        | opcode1
    )

    return instr.to_bytes(4, byteorder='little')


def get_addi0(data):
    """Генерирует байтовое представление инструкции ADDI rd, rs1, 0."""
    rd, rs1 = data
    opcode1 = 0b0010011
    opcode2 = 0b000
    imm = 0

    instr = (imm << 20) | (rs1 << 15) | (opcode2 << 12) | (rd << 7) | opcode1

    return instr.to_bytes(4, byteorder='little')

# 🚀 Watermark RISC-V

**🔍 Python tool for embedding hidden messages in RISC-V ELF binaries**  

---

## 🛠 Installation

```bash
git clone https://github.com/ylab-nsu/ws25-watermark
cd ws25-watermark
pip install -e .
```

---

## 🎯 Usage

### 🔹 Encoding Messages

```bash
riscv-watermark -e "your_message" -m method_name elf_file [-o output_file]
```

### 🔹 Decoding Messages

```bash
riscv-watermark -d -m method_name patched_elf_file
```

### 🔹 Checking Encoding Capacity

Check the maximum number of bits that can be encoded using a specific method:

```bash
riscv-watermark -g -m method_name elf_file
```

### Example

```bash
$ riscv-watermark -e "Hello" -m equal_funcs example_bins/example.elf
23:32 - INFO - riscv_watermark.main - Available max bit capacity: 42 bits
23:32 - INFO - riscv_watermark.main - Message size: 40 bits
23:32 - INFO - riscv_watermark.encoder - Successfully encoded message using EquivalentInstructionWatermarker
23:32 - INFO - riscv_watermark.main - Creating patched file: example_bins/example.elf.patched
23:32 - INFO - riscv_watermark.main - Message successfully encoded in example_bins/example.elf.patched

$ riscv-watermark -d -m equal_funcs example_bins/example.elf.patched
Decoded message: Hello
25:15 - INFO - riscv_watermark.main - Message successfully decoded

$ riscv-watermark -g -m equal_funcs,stack example_bins/sqlite3.elf
26:50 - INFO - riscv_watermark.main - Available bits for EquivalentInstructionWatermarker: 5696 (712 characters)
26:50 - INFO - riscv_watermark.main - Available bits for StackWatermarker: 0 (0 characters)
```

---

## 🧩 How It Works

The program embeds hidden messages by replacing machine instructions with their functionally equivalent counterparts, thereby modifying the binary code without changing the program's behavior.

### 🔹 Equivalent Instruction Technique

The primary watermarking method (`equal_funcs`) works by substituting machine instructions with functionally equivalent alternatives:

| Original Instruction | Equivalent Replacement | Bit Encoding |
|----------------------|------------------------|--------------|
| `addi rd, rs1, 0`    | `add rd, rs1, x0`      | 0            |
| `add rd, rs1, x0`    | `addi rd, rs1, 0`      | 1            |
| `c.nop`              | `c.or x8, x8`          | 01           |
| `c.nop`              | `c.andi x8, 0b011111`  | 10           |
| `c.nop`              | `c.and x8, x8`         | 11           |

Each substitution encodes specific bit patterns (0/1 for add/addi replacements, and 2-bit patterns for c.nop replacements), allowing messages to be hidden within the instruction stream.

---

## 🔥 Development Roadmap

Currently, the project has one fully-implemented watermarking method based on instruction replacement. Future development includes:

- [ ] Finish code refactoring
- [ ] Stack Frame Modification: A new module that will encode information by altering stack frame sizes.
- [ ] Binary Data Support: Adding support for encoding arbitrary binary data
- [ ] Robustness Testing: Ensuring watermarks survive optimization and binary manipulation
- [ ] More Watermarking Techniques: Research and implementation of additional steganographic methods

---

## 🏎️ Performance Impact

Benchmarks show that replacing instructions with functionally equivalent alternatives has negligible impact on execution speed in most real-world applications.

![Watermark RISC-V](https://i.imgur.com/QVnxOlj.png)

---

## 💡 Additional information

- The project is specifically designed for RISC-V ELF binaries
- Written in Python with minimal external dependencies

---

## 👨‍💻 Authors & Contacts

- 📌 Developed within the **YLab NSU** framework

---

**🔗 Project repository:**  
[![GitHub Repo](https://img.shields.io/badge/GitHub-Watermark%20RISC--V-blue?style=for-the-badge&logo=github)](https://github.com/ylab-nsu/ws25-watermark)

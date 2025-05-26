# Limitations of the Equivalent Instruction Substitution Method for Embedding Watermarks in RISC-V Executable Files

## Abstract

The method of substituting equivalent instructions is used to hide information inside executable files without changing their behavior. However, the RISC-V architecture has some limitations that make this method hard to use. This paper explains the RISC-V features that prevent adding more useful instruction replacements and why it is almost impossible to find new equivalents that can be used in practice.

---

## 1. Introduction

Embedding watermarks into binary files without breaking their functionality is an important task in protecting intellectual property. One way to do this is by replacing instructions with other instructions that do the same thing.

But the RISC-V architecture has a minimal and strict structure that makes this method hard to use. In the **ws25-watermark** project, a basic set of equivalent instructions was created. After that, it became clear that finding new equivalents was not useful.

---

## 2. Minimalism of RISC-V Architecture

Main features of the RISC-V architecture that make it difficult to find more equivalent instructions:

- **Minimal instruction set.** The architecture does not have duplicate or synonym instructions.
- **Strict structure.** Each instruction has a fixed meaning and format.
- **Fixed length.** Instructions have the same size, so there is no flexibility for substitutions.

---

## 3. Problems with Finding New Equivalents

In theory, some single replacements are possible (for example, `mv x1, x1` ↔ `addi x1, x1, 0`), but using them requires:

- Making sure the instruction does not change addresses, such as jumps, stack use, or data access;
- Static context — the instruction must be outside loops, branches, or macros, where its behavior could change during execution;

📌 These situations are **very rare** in real code, so the method is **not effective for hiding much information**.

---

## 4. Compiler Behavior

RISC-V optimizing compilers (like GCC, Clang):

- **Remove simple instructions** (like `mv x0, x0`);
- **Combine instructions** to make code smaller;
- **Reduce redundancy**, making it hard to find good places for substitution.

As a result, even theoretically possible equivalents **almost never appear in compiled ELF files**.

---

## 5. Conclusion

RISC-V is an architecture made for efficiency and clarity. These goals are reached by reducing the flexibility needed for using equivalent instructions effectively:

- Some equivalents exist, but **very few**;
- New equivalents **can be used only in rare cases**, and even then:
  - it is hard to keep the same behavior;
  - there is a risk of breaking program logic;
  - the possible amount of hidden information **does not grow much**.

So, **adding new equivalents is possible, but not useful**: their rarity and strict usage rules make this method almost useless in RISC-V.

---

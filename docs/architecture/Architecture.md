```text
THIS IS DRAFT DOCUMENT
Later it will be moved to the main documentation
```

# Project Architecture

Project architecture is using extensible and maintainable design patterns to provide a clear and easy way to add new watermarking methods.

Diagram below shows the new architecture class diagram:
![New Architecture](./pics/Watermark_new.png)

Old architecture and its flaws are described in the [Architecture Rework Report](./ArchRework.md).

Folder orgainization is as follows:

```text
watermark_framework/
├── architecture.py          # Defines Architecture enum (e.g., RISCV64, X86_64)
├── io/
│   ├── loader.py            # TextSectionHandler imports Architecture
│   └── writer.py
├── core/
│   └── service.py           # WatermarkService imports Architecture
└── watermarkers/
    ├── interface.py         # Watermarker interface uses Architecture
    └── eq_instr/
        ├── riscv.py         # Imports Architecture for RISCV64
        └── x86.py           # Imports Architecture for X86_64
```

## Main Design Decisions

### Strategy Pattern

Use of Strategy Pattern is obvious in our project, because we are aiming to provide multiple watermarking strategies and easy way to add new ones.

As a Context class we define `WatermarkService` class, which is responsible for managing the watermarking process and is the main entry point for the user to interact with.

![WatermarkService](./pics/Watermarker_Strategy.png)

We choosed a model in which user is responsible for initializing concrete `Watermarker` implementations, and then passing it to the `encode()`/`decode()` methods.

User gets this concrete implementations by:

- Using Builtin methods (discussed below)
- Providing implementation class by himself

### TextSection Object

The `TextSection` object is a structured data container that holds all the essential information about the `.text` section of an ELF binary.

This is overview of our small `IO/Disassembly` layer:
![TextSection](./pics/Watermark_Section_Handler.png)

The `TextSectionHandler` is a utility class with such responsibilities:

- Loading the `TextSection`:
  - Reads the ELF file and extracts the .text section's data and metadata.
  - Detects the binary's architecture and configures Capstone for disassembly.
  - Creates and returns a populated `TextSection` object.
- Writing the Modified file:
  - Takes the modified .text section data and patches it back into a new ELF file at the correct offset.
  - Preserves the rest of the original file structure.

Overview of the `TextSection` fields:

| Field      | Type            | Description |
|------------|-----------------|-------------|
| `data`     | `bytes`         | The raw byte content of the `.text` section.|
| `insns`    | `List[CsInsn]`  | A list of disassembled instructions, where each instruction is a Capstone `CsInsn` object. |
| `vma`      | `int`           | The Virtual Memory Address (VMA) where the `.text` section is loaded in memory during execution.|
| `offset`   | `int`           | The file offset where the `.text` section begins in the ELF binary. Used when patching the file with modified data.|
| `size`     | `int`           | The size of the `.text` section in bytes. |
| `arch`     | `Architecture`  | The architecture of the binary (e.g., RISC-V 64-bit, RISC-V 32-bit), represented as an enum.|
| `src_path` | `str`           | The file path of the original ELF binary, stored for reference during file writing operations.|

### Support for Multiple Architectures

Our team decided to add support for multiple architectures, because we are aiming to provide a generic solution that can be used on different platforms.  

Key player in this is the `TextSectionHandler` class, which is responsible for detecting the architecture and configuring Capstone for disassembly.

Additionally, we define at top level an `Architecture` enum that provides a clear and easy way to identify the architecture of the binary.

![Architecture Enum](./pics/Watermark_Architecture.png)

Each member of `Architecture` Enum defines metadata for an architecture, including its name, Capstone disassembler constants, and ELF header identifiers.

> The `e_machine` and `elf_class` fields are primarily used internally by `from_elf` to map ELF headers to architectures, but are public for debugging or advanced use cases.

| Attribute        | Type           | Description |
|------------------|----------------|-------------|
| `name`           | `str`          | Human-readable architecture name (e.g., "riscv64").|
| `capstone_arch`  | `int`          | Capstone architecture constant (e.g., `CS_ARCH_RISCV`).|
| `capstone_mode`  | `int`          | Capstone mode constant (e.g., `CS_MODE_RISCV64`).|
| `e_machine`      | `int`          | ELF machine type (e.g., `EM_RISCV`).|
| `elf_class`      | `Optional[int]`| ELF class (32 or 64) or `None` if not applicable.|

Each Watermarker implementation is responsible for providing its supported architecture in the `SUPPORTED_ARCHS` field.

```python
    SUPPORTED_ARCHS = { Architecture.RISCV64, Architecture.X86_64 }
```

### Extension Policy

- enums!!!

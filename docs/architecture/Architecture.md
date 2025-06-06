# 🏗️ Project Architecture

## 📋 Table of Contents

- [Overview](#-overview)
- [Folder Organization](#-folder-organization)
- [Main Design Decisions](#-main-design-decisions)
  - [Strategy Pattern](#strategy-pattern)
  - [TextSection Object](#textsection-object)
  - [Support for Multiple Architectures](#support-for-multiple-architectures)
  - [Extension Policy](#extension-policy)

## 📖 Overview

The project architecture uses extensible and maintainable design patterns to provide a clear and easy way to add new watermarking methods.

The diagram below shows the architecture class diagram:

![New Architecture](./pics/Watermark_new.png)

> **Note:** This UML was created using [draw.io](https://app.diagrams.net/) and can be accessed [here](./drawio/Watermark_new.drawio) via the draw.io GitHub integration.

📚 **Additional Resources:**

- Old architecture and its flaws are described in the [Architecture Rework Report](./ArchRework.md)

> [!NOTE]
> This documentation focuses on the new refactored architecture. For historical context and rationale behind the redesign, see the Architecture Rework Report.

## 📁 Folder Organization

The framework follows a modular structure organized by functionality:

```text
watermark_framework/
├── __init__.py              # Package initialization, exports key classes (e.g., WatermarkService)
├── architecture.py          # Defines the Architecture enum (e.g., RISCV64, X86_64)
├── io/
│   └── section_handler.py   # SectionHandler, TextSection
├── core/
│   └── service.py           # WatermarkService, main entry point
├── watermarkers/
│   ├── __init__.py          # Exports built-in Watermarker strategies
│   ├── interface.py         # Defines the Watermarker Interface
│   ├── eq_instr/
│   │   ├── common.py        # EquivalentInstructionWatermarker
│   │   └── handlers.py      # Architecture-specific handlers (if needed)
│   └── stack/
│       ├── common.py
│       └── handlers.py      
└── cli/                     # CLI Layer
    └── main.py
```

**📁 Quick Links to Source Code:**
- [📦 Package Init](../../watermark_framework/__init__.py) - Main exports and package configuration
- [🏛️ Architecture Enum](../../watermark_framework/architecture.py) - Architecture definitions and ELF mapping
- [📄 TextSection Handler](../../watermark_framework/io/section_handler.py) - ELF parsing and section management
- [⚙️ WatermarkService](../../watermark_framework/core/service.py) - Main service class and strategy management
- [🔌 Watermarker Interface](../../watermark_framework/watermarkers/interface.py) - Base interface for all watermarkers
- [🔧 Watermarkers Init](../../watermark_framework/watermarkers/__init__.py) - Built-in strategy exports
- [🖥️ CLI Main](../../watermark_framework/cli/main.py) - Command-line interface

## 🎯 Main Design Decisions

### Strategy Pattern

Use of Strategy Pattern is obvious in our project, because we are aiming to provide multiple watermarking strategies and an easy way to add new ones.

As a Context class, we define the [`WatermarkService`](../../watermark_framework/core/service.py) class, which is responsible for managing the watermarking process and is the main entry point for the user to interact with.

![WatermarkService](./pics/Watermarker_Strategy.png)

#### How we manage strategies

In the Strategy Pattern, the *Context* (in our case, [`WatermarkService`](../../watermark_framework/core/service.py)) delegates the watermarking logic to a *Strategy* (implemented by classes adhering to the [`Watermarker`](../../watermark_framework/watermarkers/interface.py) interface).

This allows the framework to support multiple watermarking algorithms interchangeably, with the flexibility to add new strategies without modifying the core service.

We chose a model where the **user is responsible for initializing** concrete `Watermarker` implementations and passing these instances to `WatermarkService`.

This approach of passing instances instead of classes ensures maximum flexibility, as **users can configure strategies with custom parameters**.

> [!TIP]
> For example: configuring equivalent instructions for [`EquivalentInstructionWatermarker`](../../watermark_framework/watermarkers/eq_instr/common.py).

#### Strategy Instance Management

1. **Passing Instances to `encode()` and `decode()`**:
   - The `encode()` and `decode()` methods accept a `Watermarker` instance, which must implement the `Watermarker` interface.
   - Users can create and configure their own instances of `Watermarker` and pass them directly to these methods. Or use built-in strategies.

2. **Passing Instances to the Constructor**:
   - The `WatermarkService` constructor accepts an optional `Watermarker` instance, allowing users to set a default strategy at initialization.

3. **Dynamic Strategy and File Switching with `set_strategy()` and `set_file()`**:
   - To enhance usability, `WatermarkService` provides two setter methods:
     - `set_strategy(strategy: Watermarker)`: Updates the current strategy, validating that it's a valid `Watermarker` instance and compatible with the loaded file’s architecture.
     - `set_file(path: str)`: Loads a new ELF file, updating the internal `TextSection` and ensuring compatibility with the current strategy (if set).

Examples with pseudo-python code that provide a better understanding of the used pattern:

#### Use of built-in watermarker with default configuration

```python
from watermark_framework import WatermarkService
from watermark_framework.watermarkers import EquivalentInstructionWatermarker

svc = WatermarkService("example.elf")

patched = svc.encode("secret", EquivalentInstructionWatermarker())
print(f"Patched: {patched}")

svc.set_file(patched)

decoded = svc.decode(EquivalentInstructionWatermarker())
print(f"Decoded: {decoded}")
```

Example of **passing Watermarker instance to constructor**:

```python
from watermark_framework import WatermarkService
from watermark_framework.watermarkers import EquivalentInstructionWatermarker

svc = WatermarkService("example.elf", EquivalentInstructionWatermarker())

patched = svc.encode("secret")
print(f"Patched: {patched}")

svc.set_file(patched)

decoded = svc.decode()
print(f"Decoded: {decoded}")
```

**Changing the strategy** after initialization is also possible:

```python
from watermark_framework import WatermarkService
from watermark_framework.watermarkers import EquivalentInstructionWatermarker, StackWatermarker

svc = WatermarkService("example.elf", EquivalentInstructionWatermarker())

patched = svc.encode("secret")
print(f"Patched with eq_instr: {patched}")

svc.set_strategy(StackWatermarker())

patched_stack = svc.encode("secret")
print(f"Patched with stack watermarker: {patched_stack}")
```

#### Use of built-in watermarker with custom configuration

Because we are passing to `encode()`/`decode()` instances of `Watermarker` class, we can easily configure them with custom parameters in the constructor.

Such as configuring equivalent instructions for [`EquivalentInstructionWatermarker`](../../watermark_framework/watermarkers/eq_instr/common.py):

```python
from watermark_framework import WatermarkService
from watermark_framework.watermarkers import EquivalentInstructionWatermarker

svc = WatermarkService("example.elf")

equiv_insns = [
    (..., ...),
    (..., ...),
    ...
]
custom_strategy = EquivalentInstructionWatermarker(equivalent_instructions=equiv_insns)

patched = svc.encode("secret", custom_strategy)

svc.set_file(patched)
decoded = svc.decode(custom_strategy)
```

#### Use of custom watermarker

```python
from my_watermarker import MyCustomWatermarker

svc = WatermarkService("example.elf")

patched = svc.encode("secret", MyCustomWatermarker())
print(f"Patched: {patched}")
```

### TextSection Object

The [`TextSection`](../../watermark_framework/io/section_handler.py) object is a structured data container that holds all the essential information about the `.text` section of an ELF binary.

This is an overview of our small `IO/Disassembly` layer:

![TextSection](./pics/Watermark_Section_Handler.png)

The [`TextSectionHandler`](../../watermark_framework/io/section_handler.py) is a utility class with such responsibilities:

- **Loading the `TextSection`**:
  - Reads the ELF file and extracts the .text section's data and metadata.
  - Detects the binary's architecture and configures Capstone for disassembly.
  - Creates and returns a populated `TextSection` object.
- **Writing the Modified file**:
  - Takes the modified .text section data and patches it back into a new ELF file at the correct offset.
  - Preserves the rest of the original file structure.

Overview of the `TextSection` fields:

| Field      | Type            | Description |
|------------|-----------------|-------------|
| `data`     | `bytes`         | The raw byte content of the `.text` section. |
| `insns`    | `List[CsInsn]`  | A list of disassembled instructions, where each instruction is a Capstone `CsInsn` object. |
| `vma`      | `int`           | The Virtual Memory Address (VMA) where the `.text` section is loaded in memory during execution. |
| `offset`   | `int`           | The file offset where the `.text` section begins in the ELF binary. Used when patching the file with modified data. |
| `size`     | `int`           | The size of the `.text` section in bytes. |
| `arch`     | `Architecture`  | The architecture of the binary (e.g., RISC-V, X86), represented as an enum. |
| `src_path` | `str`           | The file path of the original ELF binary, stored for reference during file writing operations. |

### Support for Multiple Architectures

Our team decided to add support for multiple architectures because we are aiming to provide a generic solution that can be used on different platforms.

The key player in this is the [`TextSectionHandler`](../../watermark_framework/io/section_handler.py) class, which is responsible for detecting the architecture and configuring Capstone for disassembly.

Additionally, we define at the top level an [`Architecture`](../../watermark_framework/architecture.py) enum that provides a clear and easy way to identify the architecture of the binary.

![Architecture Enum](./pics/Watermark_Architecture.png)

Each member of the `Architecture` Enum defines metadata for an architecture, including its name, Capstone disassembler constants, and ELF header identifiers.

> [!NOTE]
> The `e_machine` and `elf_class` fields are primarily used internally by `from_elf` to map ELF headers to architectures, but are public for debugging or advanced use cases.

| Attribute        | Type           | Description |
|------------------|----------------|-------------|
| `name`           | `str`          | Human-readable architecture name (e.g., "riscv"). |
| `capstone_arch`  | `int`          | Capstone architecture constant (e.g., `CS_ARCH_RISCV`). |
| `capstone_mode`  | `int`          | Capstone mode constant (e.g., `CS_MODE_RISCV64`). |
| `e_machine`      | `str`          | ELF machine type (e.g., `"EM_RISCV"`). |
| `elf_class`      | `Optional[int]`| ELF class (32 or 64) or `None` if not applicable. |

> `Architecture` also has a class method: `from_elf(e_machine: str, elf_class: int) -> Architecture`
>
> It maps ELF header values (`e_machine` and `elf_class`) to an `Architecture` member. (used by [`TextSectionHandler`](../../watermark_framework/io/section_handler.py))

Each Watermarker implementation is responsible for providing its supported architecture in the `SUPPORTED_ARCHS` field.

```python
SUPPORTED_ARCHS = { Architecture.RISCV64, Architecture.X86_64 }
```

As developers of the framework, **we guarantee that only supported architectures will be passed to the Watermarker class**. This means you can safely omit the check for unsupported architectures in your code.

> [!IMPORTANT]
> Each Watermarker implementation must define its supported architectures in the `SUPPORTED_ARCHS` field. The framework will automatically validate compatibility before executing watermarking operations.

We describe how to support multiple architectures in your Watermarker and provide guidelines in the [How to write a Watermarker](./../HowToWatermarker.md) document.

### Extension Policy

The Watermark framework is designed to be easily extensible, allowing users and developers to add new watermarking strategies without modifying the core codebase.

We've defined a clear policy for extending the framework with new `Watermarker` implementations, aiming for two primary audiences:

- End users who use the library through a package manager (in the future pip)
- Developers contributing to the framework's repository

#### Extension for End Users

For users who install the Watermark framework as a package, the primary way to extend the framework is by creating a custom `Watermarker` implementation and passing an instance of it to `WatermarkService`.

Guidelines for creating a custom Watermarker are provided in the [How to write a Watermarker](./../HowToWatermarker.md) document.

This approach is straightforward and doesn't require modifying the library's code:

1. **Create a Custom Watermarker**:
   - Users implement a new class that inherits from the [`Watermarker` interface](../../watermark_framework/watermarkers/interface.py) (defined in `watermark_framework.watermarkers.interface`).
   - Detailed guidelines: [How to write a Watermarker](./../HowToWatermarker.md).

2. **Use the Custom Watermarker**:
   - Users instantiate their custom Watermarker and pass it to [`WatermarkService`](../../watermark_framework/core/service.py)'s `encode()`, `decode()`, or `set_strategy()` methods, or provide it to the constructor.

#### Extension for Framework Developers (Repository Contributors)

For developers contributing to the Watermark framework (e.g., those working with the full repository), the process for adding new built-in strategies is more structured to ensure consistency and maintainability:

1. **Create a New Watermarker Class**:
   - Developers create a new class in the [`watermark_framework/watermarkers`](../../watermark_framework/watermarkers) directory, following the naming convention of existing classes (e.g., `MyCustomWatermarker`).
   - Detailed guidelines: [How to write a Watermarker](./../HowToWatermarker.md).

2. **Export the New Watermarker**:

   Export the new strategy in [`watermark_framework/watermarkers/__init__.py`](../../watermark_framework/watermarkers/__init__.py) to make it importable in user code:

   ```python
   from .new_strategy import NewWatermarker
   ```

   Without manual export, it will still be accessible via `get_watermarkers` in [`watermark_framework/watermarkers/__init__.py`](../../watermark_framework/watermarkers/__init__.py), which dynamically collects all classes that implement the `Watermarker` interface. (this is used in the implementation of the CLI Layer).

3. **Update Documentation**:
   - Document the new strategy in the framework's documentation, including its purpose, configuration options, and example usage.
   - `TODO:` link

#### CLI Extension

> [!WARNING]
> **TODO:** Describe CLI Layer module to parse .py file and extract custom Watermarker implementation.

The CLI can parse a file or directory containing Watermarker implementations.

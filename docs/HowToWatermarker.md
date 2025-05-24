
## Incomind data convintions

- already checked for capacity
- only BYTES

## Supporting Multiple Architectures

Here we present our recommendations for how to implement support for multiple architectures in a watermarking strategy.

Of course you can just write huge switch-case statements, but that is not the best practice and because of that we provide our design guidelines.

As developers of framework we **GUARANTEE that only supported architectures will be passed to the Watermarker** class. So you can safely omit the check for unsupported architectures in your code.

### Option 1: Simple if-else for 2-3 Architectures

For strategies that only need to support a small number of architectures (e.g., RISCV64 and X86_64), we can avoid registries altogether and implement the logic directly in the Watermarker class using if-else statements. This is the simplest possible approach because it requires no additional classes or mappings

```python
# watermark_framework/watermarkers/eq_instr/common.py
from watermark_framework.watermarkers.interface import Watermarker
from watermark_framework.architecture import Architecture

class EquivalentInstructionWatermarker(Watermarker):
    METHOD_NAME = "eq_instr"
    SUPPORTED_ARCHS = {Architecture.RISCV64, Architecture.X86_64}

    def __init__(self, equivalent_instructions=None):
        self._equiv_insns = equivalent_instructions

    def get_nbits(self, section):
        equiv_insns = self._equiv_insns or get_default_insns(section.arch)
        if section.arch == Architecture.RISCV64:
            # RISC-V-specific logic
        elif section.arch == Architecture.X86_64:
            # x86-specific logic

    def encode(self, section, message):
        equiv_insns = self._equiv_insns or get_default_insns(section.arch)
        if section.arch == Architecture.RISCV64:
            # RISC-V-specific encoding
        elif section.arch == Architecture.X86_64:
            # x86-specific encoding

    def decode(self, section):
        equiv_insns = self._equiv_insns or get_default_insns(section.arch)
        if section.arch == Architecture.RISCV64:
            # RISC-V-specific decoding
        elif section.arch == Architecture.X86_64:
            # x86-specific decoding
```

### Option 2: Handler Class Registry for 5-6+ Architectures

This case is less likely to occur in current state of the project, but it is worth mentioning. For strategies that need to support many architectures (e.g., RISCV64, X86_64, ARM64, and more), we can use a **handler class-based registry**.

- Each architecture has a dedicated handler class that encapsulates its specific logic.
- The Watermarker class maintains a dictionary mapping architectures to these handler classes and delegates method calls to the appropriate handler.

```python
# watermark_framework/watermarkers/eq_instr/handlers.py
from watermark_framework.architecture import Architecture
from watermark_framework.watermarkers.interface import BaseHandler

class RiscvHandler(BaseHandler):
    def __init__(self, equiv_insns):
        self.equiv_insns = equiv_insns

    def get_nbits(self, section):
        # RISC-V-specific logic

    def encode(self, section, message):
        # RISC-V-specific encoding

    def decode(self, section):
        # RISC-V-specific decoding

class X86Handler(BaseHandler):
    def __init__(self, equiv_insns):
        self.equiv_insns = equiv_insns

    def get_nbits(self, section):
        # x86-specific logic

    def encode(self, section, message):
        # x86-specific encoding

    def decode(self, section):
        # x86-specific decoding
```

```python
# watermark_framework/watermarkers/eq_instr/common.py
from watermark_framework.watermarkers.interface import Watermarker
from watermark_framework.architecture import Architecture
from .handlers import RiscvHandler, X86Handler

class EquivalentInstructionWatermarker(Watermarker):
    METHOD_NAME = "eq_instr"
    _ARCH_HANDLERS = {
        Architecture.RISCV64: RiscvHandler,
        Architecture.X86_64: X86Handler,
    }
    SUPPORTED_ARCHS = set(_ARCH_HANDLERS)

    def __init__(self, equivalent_instructions=None):
        self._handlers = {
            arch: handler(equivalent_instructions or get_default_insns(arch))
            for arch, handler in self._ARCH_HANDLERS.items()
        }

    def get_nbits(self, section):
        handler = self._handlers.get(section.arch)
        return handler.get_nbits(section)

    def encode(self, section, message):
        handler = self._handlers.get(section.arch)
        return handler.encode(section, message)

    def decode(self, section):
        handler = self._handlers.get(section.arch)
        return handler.decode(section)
```

In this example we have a class-level dictionary `_ARCH_HANDLERS`:

```python
    _ARCH_HANDLERS = {
        Architecture.RISCV64: RiscvHandler,
        Architecture.X86_64: X86Handler,
    }
```

In `EquivalentInstructionWatermarker` constructor we create a dictionary of handlers for each architecture:

```python
    def __init__(self, equivalent_instructions=None):
        self._handlers = {
            arch: handler(equivalent_instructions or get_default_insns(arch))
            for arch, handler in self._ARCH_HANDLERS.items()
        }
```

> `get_default_insns(arch)` is assumed to be a function (not shown in the code snippet) that returns default equivalent instructions for the given architecture.  
> It is special for this example strategy and is not part of the guideline.

The resulting self._handlers dictionary will look like this:

```python
{
    Architecture.RISCV64: <RiscvHandler instance>,
    Architecture.X86_64: <X86Handler instance>,
}
```

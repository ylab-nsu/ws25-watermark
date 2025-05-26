# Testing Strategy

## Overview

Our testing approach focuses on **isolated unit tests** with **minimal dependencies** and **comprehensive coverage** of core functionality.

## Test Structure

### Unit Tests

- **[`test_watermarkers_init.py`](../tests/test_watermarkers_init.py)** - Strategy registration and discovery
- **[`test_service.py`](../tests/test_service.py)** - Core WatermarkService functionality  
- **[`test_section_handler.py`](../tests/test_section_handler.py)** - ELF parsing and section management

### Integration Tests

- **[`test_cli.py`](../tests/test_cli.py)** - End-to-end CLI workflows
- **[`test_for_qemu.py`](../tests/test_for_qemu.py)** - Real binary execution validation

## Running Tests

```bash
make test          # Run all tests
make test-cov      # Run with coverage report
```

## Coverage & CI

- **Coverage tracking** with `pytest-cov` and detailed reporting
- **Automated testing** in CI/CD pipeline with coverage validation
- **Coverage reports** generated for all commits and pull requests

## Dependencies

- Example binaries in `example_bins/` (tests skip if missing)
- QEMU RISC-V for execution tests (optional)
- All tests use temporary directories for outputs

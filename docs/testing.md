# Test Coverage Documentation

This document describes the test coverage for the main components of the watermarking framework.

## CLI Tests (`test_cli.py`)

Tests the command-line interface functionality:

- **List Strategies**
  - Verifies the `--list` command outputs available watermarking strategies
  - Ensures "EQ_INSTR" strategy is listed

- **Binary File Handling**
  - Tests error handling for missing binary file
  - Tests error handling for non-existent binary file
  - Validates proper error messages

- **Strategy Validation**
  - Tests error handling for invalid strategy names
  - Verifies proper error messages for unknown strategies

- **Encoding/Decoding Flow**
  - Tests complete encoding cycle with message
  - Verifies successful file creation
  - Tests decoding of encoded message
  - Validates message integrity

- **Capacity Check**
  - Tests the capacity check command
  - Verifies proper output format with bits information

- **Operation Validation**
  - Tests error handling when no operation is specified
  - Validates proper error messages

## Service Tests (`test_service.py`)

Tests the core WatermarkService functionality:

- **Service Initialization**
  - Tests initialization with and without strategy
  - Validates section and strategy attributes

- **Strategy Management**
  - Tests strategy validation
  - Tests setting valid and invalid strategies
  - Verifies architecture compatibility checks

- **File Management**
  - Tests switching between files
  - Validates error handling for invalid files
  - Tests file path validation

- **Capacity Calculation**
  - Tests capacity calculation with and without strategy
  - Validates capacity calculation with explicit strategy

- **Encoding/Decoding Operations**
  - Tests message encoding
  - Tests message decoding
  - Validates message integrity
  - Tests handling of oversized messages

## Watermarker Initialization Tests (`test_watermarkers_init.py`)

Tests the watermarker initialization and management:

- **Strategy Listing**
  - Tests retrieval of available strategies
  - Verifies strategy list format and content
  - Ensures "EQ_INSTR" is available

- **Strategy Retrieval**
  - Tests getting strategy by name
  - Validates correct strategy class is returned
  - Tests error handling for non-existent strategies

- **Watermarker Dictionary**
  - Tests retrieval of watermarker dictionary
  - Verifies dictionary structure and content
  - Validates strategy class mappings

- **Duplicate Detection**
  - Tests detection of duplicate METHOD_NAME
  - Validates error handling for duplicate implementations
  - Ensures proper error messages

## QEMU Testing (`test_for_qemu.py`)

Tests the functionality of watermarked binaries using QEMU emulator:

- **Test Environment Setup**
  - Uses QEMU RISC-V 64-bit emulator
  - Requires RISC-V GNU/Linux toolchain
  - Sets up proper environment variables for QEMU

- **Test Programs**
  - Tests basic programs like `echo` and `cat`
  - Verifies program functionality after watermarking
  - Checks program output matches expected results

- **Test Flow**
  1. Loads original RISC-V binary
  2. Applies watermarking with test message
  3. Runs watermarked binary in QEMU
  4. Verifies program output and functionality
  5. Cleans up temporary files

- **Test Cases**
  - `echo.elf`: Tests basic string output
  - `cat.elf`: Tests file reading functionality
  - Each test verifies:
    - Program executes successfully
    - Output matches expected results
    - Watermark doesn't affect functionality

## Test Dependencies

- Tests require example binaries in the `example_bins` directory
- Some tests are skipped if required binaries are not found
- Tests use temporary directories for output files
- Tests verify both successful operations and error conditions
- QEMU tests require:
  - QEMU RISC-V 64-bit emulator
  - RISC-V GNU/Linux toolchain
  - Proper environment setup for QEMU 
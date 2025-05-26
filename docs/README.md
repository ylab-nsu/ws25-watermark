# 📚 ELF Watermarking Framework Documentation

Welcome to the comprehensive documentation for the ELF Watermarking Framework. This guide will help you understand, use, and extend the framework.

## 🎯 Getting Started

- **[🏗️ Architecture Overview](./architecture/Architecture.md)** - Framework design and components
- **[🔧 How to Implement a Watermarker](./HowToWatermarker.md)** - Create custom watermarking strategies
- **[🔄 Architecture Rework Report](./architecture/ArchRework.md)** - Migration from old to new design

### Core Classes

- **[`WatermarkService`](../watermark_framework/core/service.py)** - Main service class implementing Strategy pattern
- **[`TextSection`](../watermark_framework/io/section_handler.py)** - ELF .text section data container
- **[`Watermarker`](../watermark_framework/watermarkers/interface.py)** - Base interface for watermarking strategies
- **[`Architecture`](../watermark_framework/architecture.py)** - Architecture enumeration and metadata

---

## Development Setup

```bash
git clone <repository-url>
cd ws25-watermark
poetry install --with dev
```

### 🛠️ Development Tools

The project includes a comprehensive Makefile with development commands:

```bash
# Installation
make install          # Install project dependencies
make dev-install      # Install development dependencies

# Code Quality
make format           # Format code with Ruff (auto-fix)
make lint             # Lint code with Ruff (no auto-fix)
make type-check       # Run type checking with mypy
make type-check-report # Type checking with detailed error report

# Testing
make test             # Run tests
make test-cov         # Run tests with coverage report

# Maintenance
make clean            # Clean up generated files
make all              # Run all checks (format, lint, type-check, test)
make ci               # Run CI checks (lint, type-check, test) - no formatting
```

### Quick Start Development Workflow

```bash
# Setup development environment
make dev-install

# Before committing changes
make all              # Runs format, lint, type-check, and tests
```

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

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Understand the Architecture**: Read the [Architecture Documentation](./architecture/Architecture.md)
2. **Implement a Watermarker**: Follow the [Watermarker Implementation Guide](./HowToWatermarker.md)
3. **Follow Standards**: Use consistent code style and documentation
4. **Test Your Changes**: Ensure all tests pass and add new tests for new features

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/ylab-nsu/ws25-watermark
cd ws25-watermark
poetry install

# Run tests
python -m pytest
```

---

## 📖 Additional Resources

- **[Architecture Rework Report](./architecture/ArchRework.md)** - Details about the framework redesign

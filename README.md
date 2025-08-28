# Cumpyl Framework

![Cumpyl Demo](images/sexy1.png)
![Cumpyl Interface](images/sexy2.png)

Cumpyl is a powerful Python-based binary analysis framework for analyzing, modifying, and rewriting binary files (PE, ELF, Mach-O). It features a plugin architecture, batch processing capabilities, and comprehensive reporting functions.

## Key Features

- **Multi-format Support**: Native support for PE, ELF, and Mach-O binaries
- **Plugin Architecture**: Extensible plugin system for analysis and transformation
- **Interactive Menu System**: Guided interface for all framework capabilities
- **Batch Processing**: Multi-threaded processing of multiple files
- **Advanced Encoding**: Multiple encoding methods for obfuscation
- **Dual-Mode Hex Viewer**: Terminal TUI and browser-based hex viewing
- **Comprehensive Reporting**: HTML, JSON, YAML, and XML report generation
- **YAML Configuration**: Flexible configuration with predefined profiles

## Installation

### Prerequisites

- Python 3.9 or higher
- pip or uv package manager

### Modern Installation (Recommended with uv)

```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and install
git clone https://github.com/umpolungfish/cumpyl.git
cd cumpyl
uv sync  # Creates virtual environment and installs all dependencies

# Activate environment
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### Traditional Installation

```bash
git clone https://github.com/umpolungfish/cumpyl.git
cd cumpyl
pip install -e .
```

## Quick Start

The easiest way to get started with Cumpyl is to use the interactive menu system:

```bash
cumpyl sample.exe --menu
```

This will launch a guided interface that provides access to all of Cumpyl's features.

## Interactive Menu System

Cumpyl features a rich interactive menu system that provides guided access to all framework capabilities:

1. **Quick Analysis**: Fast section analysis and obfuscation suggestions
2. **Deep Analysis**: Comprehensive plugin-based analysis with reporting
3. **Interactive Hex Viewer**: Explore binary with interactive hex dump
4. **Batch Processing**: Process multiple files with automated workflows
5. **Encoding Operations**: Obfuscate specific sections with various encodings
6. **Binary Packers**: Analyze and pack binaries with compression and encryption
7. **Report Generation**: Create detailed analysis reports in multiple formats
8. **Configuration**: View and modify framework settings
9. **Change Target**: Select a different binary file

### Plugin-Based Packer Menu

The Binary Packers option includes a plugin-based packer menu that supports:
- Analysis with packer plugins
- Transformation with packer plugins
- Real packer integration as fallback
- Support for PE, ELF, and Mach-O formats

To access the plugin packer menu directly, run:

```bash
python3 plugin_packer_menu.py [binary_file]
```

## Command Line Interface

Cumpyl provides a comprehensive command-line interface for binary analysis and manipulation.

### Basic Analysis

```bash
cumpyl binary.exe --analyze-sections
```

Analyze binary structure and sections.

### Obfuscation Suggestions

```bash
cumpyl binary.exe --suggest-obfuscation
```

Get intelligent section encoding recommendations.

### Hex View

```bash
cumpyl binary.exe --hex-view
```

Generate interactive hex viewer.

### Comprehensive Analysis

```bash
cumpyl binary.exe --hex-view --run-analysis --suggest-obfuscation
```

Run comprehensive analysis with interactive hex view.

### Reporting

```bash
cumpyl binary.exe --run-analysis --report-format html --report-output analysis.html
```

Run comprehensive analysis with HTML report output.

## Plugin System

Cumpyl's plugin system allows for extensible analysis and transformation capabilities:

- **Entropy Analysis**: Calculate Shannon entropy for packed binary detection
- **String Extraction**: Advanced string extraction with context scoring
- **Section Analysis**: Automatic classification and safety assessment
- **Packer Detection**: Identify potential packing techniques
- **Go Binary Analysis**: Specialized analysis for Go binaries
- **CGO Analysis**: Analysis for CGO-enabled Go binaries

Each plugin can be configured with options such as:
- Compression level (1-9)
- Encryption key path for secure transformations
- Safe mode and dry run options for testing
- Section skipping preferences

## Batch Processing

Process multiple files efficiently with Cumpyl's batch processing capabilities.

### Directory Processing

```bash
cumpyl --batch-directory /samples --batch-operation plugin_analysis --report-format json
```

Process all binaries in a specified directory.

### Pattern-based Processing

```bash
cumpyl --batch-pattern "*.exe" --batch-pattern "*.dll" --batch-operation analyze_sections
```

Process files matching glob patterns.

### Recursive Processing

```bash
cumpyl --batch-directory /dataset --batch-extensions ".exe,.dll" --batch-recursive
```

Recursive processing with custom extensions.

## Encoding and Obfuscation

Cumpyl provides advanced encoding and obfuscation capabilities for binary sections.

### Supported Encodings

- **Hex**: Simple hexadecimal encoding
- **Octal**: Octal escape sequence encoding
- **Null**: Null byte padding
- **Base64**: Standard Base64 encoding
- **Compressed Base64**: Zlib compression + Base64 encoding

### Section Encoding

```bash
cumpyl binary.exe --encode-section .text --encoding base64 -o encoded.exe
```

Encode specific sections.

### Multi-section Encoding

```bash
cumpyl binary.exe --encode-section .text --encoding base64 --encode-section .data --encoding hex
```

Apply encodings to multiple sections.

## Configuration

Cumpyl uses YAML-based configuration for flexible customization.

### Configuration File

The default configuration file is `cumpyl.yaml`:

```yaml
framework:
  version: "0.3.0"
  debug_mode: false
  verbose_logging: false
  max_file_size_mb: 100

plugins:
  enabled: true
  plugin_directory: "plugins"
  auto_discovery: true

batch:
  max_workers: 4
  default_extensions: [".exe", ".dll", ".so", ".bin", ".elf"]

hex_viewer:
  default_bytes: 2048
  max_bytes: 16384
```

### Analysis Profiles

Cumpyl includes predefined analysis profiles:

- **malware_analysis**: Advanced malware detection and analysis
- **forensics**: Digital forensics and evidence collection
- **research**: Academic research and reverse engineering

Use profiles with:
```bash
cumpyl binary.exe --profile malware_analysis --run-analysis
```

## Documentation

For detailed information about Cumpyl's features and usage, please refer to the documentation:

- [User Guide](CUMPYL_USER_GUIDE.md) - Comprehensive guide for using Cumpyl
- [Developer Guide](CUMPYL_DEVELOPER_GUIDE.md) - Information for extending Cumpyl with custom plugins
- [API Reference](CUMPYL_API_REFERENCE.md) - Detailed API documentation
- [Release Notes](CUMPYL_RELEASE_NOTES.md) - Version history and changes

## Contributing

We welcome contributions to Cumpyl! Please see the [Developer Guide](CUMPYL_DEVELOPER_GUIDE.md) for information on how to contribute.

## License

This project is released into the public domain under the Unlicense.
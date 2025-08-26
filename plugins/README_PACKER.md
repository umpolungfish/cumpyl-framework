# PE Packer Plugin

A binary packing and obfuscation plugin for the Cumpyl framework.

## Features

- Compresses PE file sections using zlib
- Encrypts sections with AES-256-CBC
- Analyzes binaries for packing opportunities
- Calculates entropy to detect pre-packed sections
- Generates unpacker stub placeholders

## Installation

The plugin is included with Cumpyl and requires no additional installation.

## Configuration

Configure the plugin in `cumpyl.yaml`:

```yaml
plugins:
  packer:
    compression_level: 6        # zlib compression level (1-9)
    encrypt_sections: true      # whether to encrypt sections
    encryption_key: null        # encryption key (null = generate random)
```

## Usage

### Command Line (conceptual)
```bash
# Analyze a binary for packing opportunities
cumpyl --analyze binary.exe --plugins packer

# Pack a binary
cumpyl --transform binary.exe --plugins packer_transform --output packed_binary.exe
```

### Programmatic Usage
```python
from plugins.packer_plugin import PackerPlugin, PackerTransformationPlugin

# Analysis
analysis_plugin = PackerPlugin(config)
analysis_result = analysis_plugin.analyze(rewriter)

# Transformation
transform_plugin = PackerTransformationPlugin(config)
transform_result = transform_plugin.transform(rewriter, analysis_result)
```

## Testing

Run the included tests:
```bash
python test_packer.py
python demo_packer.py
```

## Documentation

See `DOCS_PACKER_PLUGIN.md` for complete technical documentation.

## License

Part of the Cumpyl framework - see main project license.
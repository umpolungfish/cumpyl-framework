#!/usr/bin/env python3
\"\"\"Test the packer plugin functionality\"\"\"

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cumpyl_package'))

from plugins.packer_plugin import PackerPlugin, PackerTransformationPlugin
from cumpyl_package.config import ConfigManager

def test_packer_plugin():
    \"\"\"Test the packer plugin analysis and transformation\"\"\"
    print(\"Testing packer plugin...\")
    
    # Create config
    config = ConfigManager()
    
    # Test analysis plugin
    print(\"\\n1. Testing analysis plugin...\")
    analysis_plugin = PackerPlugin(config)
    print(f\"   Plugin name: {analysis_plugin.name}\")
    print(f\"   Plugin version: {analysis_plugin.version}\")
    print(f\"   Plugin description: {analysis_plugin.description}\")
    
    # Test analysis with no binary (should not crash)
    analysis_result = analysis_plugin.analyze(None)
    print(f\"   Analysis result keys: {list(analysis_result.keys())}\")
    print(f\"   Capabilities: {analysis_result.get('capabilities', [])}\")
    
    # Test entropy calculation
    print(\"\\n2. Testing entropy calculation...\")
    test_data = b\"Hello, World! This is a test string for entropy calculation.\"
    entropy = analysis_plugin._calculate_entropy(test_data)
    print(f\"   Test data: {test_data}\")
    print(f\"   Entropy: {entropy:.4f}\")
    
    # Test with high entropy data (random bytes)
    import random
    random_data = bytes([random.randint(0, 255) for _ in range(1000)])
    high_entropy = analysis_plugin._calculate_entropy(random_data)
    print(f\"   Random data entropy: {high_entropy:.4f}\")
    
    # Test transformation plugin
    print(\"\\n3. Testing transformation plugin...\")
    transform_plugin = PackerTransformationPlugin(config)
    print(f\"   Transform plugin name: {transform_plugin.name}\")
    print(f\"   Transform plugin version: {transform_plugin.version}\")
    print(f\"   Compression level: {transform_plugin.compression_level}\")
    print(f\"   Encrypt sections: {transform_plugin.encrypt_sections}\")
    
    # Test transform with no binary (should not crash)
    transform_result = transform_plugin.transform(None, {})
    print(f\"   Transform result: {transform_result}\")
    
    # Test unpacker stub generation
    print(\"\\n4. Testing unpacker stub generation...\")
    unpacker_stub = transform_plugin._generate_unpacker_stub()
    print(f\"   Unpacker stub size: {len(unpacker_stub)} bytes\")
    print(f\"   Unpacker stub preview: {unpacker_stub[:32]}...\")
    
    # Test save packed binary method
    print(\"\\n5. Testing save packed binary method...\")
    save_result = transform_plugin.save_packed_binary(None, \"/tmp/test_packed.exe\")
    print(f\"   Save result: {save_result}\")
    
    print(\"\\n\u00e2\u0153\u00bex All tests completed successfully!\")

if __name__ == \"__main__\"
:
    test_packer_plugin()
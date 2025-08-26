#!/usr/bin/env python3
\"\"\"Demo script showing how to use the packer plugin with a real binary\"\"\"

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cumpyl_package'))

from cumpyl_package.cumpyl import BinaryRewriter
from cumpyl_package.config import ConfigManager
from plugins.packer_plugin import PackerPlugin, PackerTransformationPlugin

def demo_packer_with_binary():
    \"\"\"Demo the packer plugin with a real binary\"\"\"
    print(\"=== PE Packer Plugin Demo ===\")
    
    # Find a test binary
    test_binaries = [
        'cutzie.exe',
        '4dglasses.exe', 
        '8dglasses.exe',
        'encoded.exe'
    ]
    
    binary_path = None
    for binary in test_binaries:
        full_path = os.path.join(os.path.dirname(__file__), binary)
        if os.path.exists(full_path):
            binary_path = full_path
            break
    
    if not binary_path:
        print(\"[-] No test binary found\")
        return
        
    print(f\"[*] Using binary: {os.path.basename(binary_path)}\")
    
    # Create config and rewriter
    config = ConfigManager()
    rewriter = BinaryRewriter(binary_path, config)
    
    # Load the binary
    if not rewriter.load_binary():
        print(\"[-] Failed to load binary\")
        return
        
    print(f\"[+] Loaded binary successfully\")
    print(f\"    Size: {len(rewriter.binary.content) if hasattr(rewriter.binary, 'content') else 'unknown'} bytes\")
    print(f\"    Sections: {len(rewriter.binary.sections)}\")
    
    # Analyze with packer plugin
    print(\"\n--- Analysis Phase ---\")
    analysis_plugin = PackerPlugin(config)
    analysis_result = analysis_plugin.analyze(rewriter)
    
    print(f\"Plugin: {analysis_result.get('plugin_name', 'unknown')}\")
    print(f\"Version: {analysis_result.get('version', 'unknown')}\")
    print(f\"Capabilities: {analysis_result.get('capabilities', [])}\")
    
    # Show analysis details
    analysis = analysis_result.get('analysis', {})
    print(f\"Binary size: {analysis.get('binary_size', 0)} bytes\")
    print(f\"Sections count: {analysis.get('sections_count', 0)}\")
    
    sections = analysis.get('sections', [])
    print(f\"\nSections:\")
    for section in sections:
        print(f\"  {section['name']:<12} {section['size']:>8} bytes  \"
              f\"{'X' if section['is_executable'] else ' '} \"
              f\"{'R' if section['is_readable'] else ' '} \"
              f\"{'W' if section['is_writable'] else ' '}\")
    
    opportunities = analysis.get('packing_opportunities', [])
    if opportunities:
        print(f\"\nPacking opportunities:\")
        for opp in opportunities:
            print(f\"  {opp['section']:<12} {opp['size']:>8} bytes  {opp['type']}\")
    
    suggestions = analysis_result.get('suggestions', [])
    if suggestions:
        print(f\"\nSuggestions:\")
        for suggestion in suggestions:
            print(f\"  {suggestion['section']:<12} {suggestion['size']:>8} bytes  \"
                  f\"{' '.join(suggestion.get('suggested_methods', []))}\")
    
    # Transform with packer plugin
    print(\"\n--- Transformation Phase ---\")
    transform_plugin = PackerTransformationPlugin(config)
    transform_result = transform_plugin.transform(rewriter, analysis_result)
    
    print(f\"Transform result: {transform_result}\")
    
    if transform_result:
        # Save packed binary
        output_path = os.path.join(os.path.dirname(__file__), \"packed_\" + os.path.basename(binary_path))
        save_result = transform_plugin.save_packed_binary(rewriter, output_path)
        print(f\"Save result: {save_result}\")
        if save_result:
            print(f\"Saved packed binary to: {output_path}\")
    
    print(\"\n=== Demo completed ===\")

if __name__ == \"__main__\":
    demo_packer_with_binary()
#!/usr/bin/env python3
"""
Demo script for payload transmutation functionality in Cumpyl Framework
Showcases the integration of the sc8r payload transmutation tool
"""

import sys
import os

# Add the project root to the path so we can import cumpyl modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cumpyl_package.transmuter import PayloadTransmuter, TransmuteConfig, TransmuteMethod, PayloadLibrary
from plugins.transmuter_plugin import transmute_payload, get_transmuter_methods

def demo_basic_transmutation():
    """Demonstrate basic payload transmutation"""
    print("=== Basic Payload Transmutation Demo ===\n")
    
    # Sample payloads
    payloads = [
        "cat /etc/passwd",
        "ls -la",
        "whoami",
        "; rm -rf /tmp/*",
        "<script>alert('XSS')</script>"
    ]
    
    # Demonstrate different encoding methods
    methods = ["hex", "base64", "unicode", "octal", "null_padding"]
    
    for payload in payloads:
        print(f"Original payload: {payload}")
        for method in methods:
            try:
                transmuted = transmute_payload(payload, method)
                print(f"  {method:15}: {transmuted}")
            except Exception as e:
                print(f"  {method:15}: Error - {e}")
        print()

def demo_mixed_encoding():
    """Demonstrate mixed encoding"""
    print("=== Mixed Encoding Demo ===\n")
    
    payload = "cat /etc/passwd"
    print(f"Original payload: {payload}")
    
    config = TransmuteConfig()
    transmuter = PayloadTransmuter(config)
    
    try:
        result = transmuter.transmute(payload, TransmuteMethod.MIXED)
        if isinstance(result, dict):
            for method, encoded in result.items():
                print(f"  {method:15}: {encoded}")
    except Exception as e:
        print(f"Error: {e}")
    print()

def demo_templates():
    """Demonstrate template payloads"""
    print("=== Template Payloads Demo ===\n")
    
    categories = PayloadLibrary.list_categories()
    print(f"Available template categories: {categories}\n")
    
    for category in categories:
        payloads = PayloadLibrary.get_payloads(category)
        print(f"{category.upper()} payloads:")
        for payload in payloads[:3]:  # Show first 3 payloads
            print(f"  - {payload}")
            
            # Transmute with hex encoding as example
            try:
                transmuted = transmute_payload(payload, "hex")
                print(f"    Hex encoded: {transmuted}")
            except Exception as e:
                print(f"    Error: {e}")
        print()

def demo_plugin_integration():
    """Demonstrate plugin integration"""
    print("=== Plugin Integration Demo ===\n")
    
    # This would typically be used within the cumpyl framework
    # For demo purposes, we'll show the available methods
    methods = get_transmuter_methods()
    print("Available transmutation methods:")
    for method in methods:
        print(f"  - {method}")
    print()

def main():
    """Main demo function"""
    print("🔒 CUMPYL FRAMEWORK - Payload Transmutation Demo 🔓\n")
    
    demo_basic_transmutation()
    demo_mixed_encoding()
    demo_templates()
    demo_plugin_integration()
    
    print("=== Demo Complete ===")
    print("\nTo use the payload transmutation tool directly:")
    print("  python -m cumpyl_package.transmuter -p \"cat /etc/passwd\" -m hex")
    print("  python -m cumpyl_package.transmuter -f payloads.txt -m base64 -o results.json")

if __name__ == "__main__":
    main()
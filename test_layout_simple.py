#!/usr/bin/env python3
"""Simple test to verify hex viewer layout fixes"""

from cumpyl_package.hex_viewer import HexViewer
from cumpyl_package.config import ConfigManager

def simulate_width_adjustment(hex_viewer, terminal_width):
    """Simulate the TextualHexViewer _adjust_bytes_per_row logic"""
    try:
        # Same logic as in _adjust_bytes_per_row
        if terminal_width <= 80:
            terminal_width = 144  # Assume wide terminal if detection fails
        
        overhead = 15
        chars_per_byte = 4.125
        available_width = terminal_width - overhead
        raw_bytes_estimate = int(available_width / chars_per_byte)
        
        # Round down to nearest 8-byte boundary
        new_bytes_per_row = (raw_bytes_estimate // 8) * 8
        
        # Enforce reasonable limits
        if new_bytes_per_row < 8:
            new_bytes_per_row = 8
        elif new_bytes_per_row > 64:
            new_bytes_per_row = 64
        
        # Add in 8 bytes if only 16 have for smaller terminal
        if new_bytes_per_row <= 16 and terminal_width > 100:
            new_bytes_per_row = 24
        
        hex_viewer.bytes_per_row = new_bytes_per_row
        
    except Exception:
        # Fallback: force 32 bytes per row (doubled from 16)
        hex_viewer.bytes_per_row = 32

def test_layout():
    """Test the layout with different simulated terminal widths"""
    print("Testing hex viewer layout fixes...")
    
    config = ConfigManager()
    hex_viewer = HexViewer(config)
    hex_viewer.load_from_file('4dglasses.exe')
    
    print(f"✓ Loaded {hex_viewer.file_path}")
    print(f"  File size: {hex_viewer.file_size:,} bytes")
    print(f"  Default bytes_per_row: {hex_viewer.bytes_per_row}")
    
    # Test with a wide terminal (like in the screenshot)
    print(f"\n🔧 Adjusting for wide terminal (180 columns)...")
    simulate_width_adjustment(hex_viewer, 180)
    print(f"  New bytes_per_row: {hex_viewer.bytes_per_row}")
    
    # Generate sample content
    print(f"\n📄 Sample hex view with {hex_viewer.bytes_per_row} bytes per row:")
    sample = hex_viewer.generate_textual_hex_view(max_bytes=hex_viewer.bytes_per_row * 3)
    lines = sample.split('\n')[:3]
    
    for i, line in enumerate(lines):
        if line.strip():
            # Count actual display characters (remove color codes)
            import re
            clean_line = re.sub(r'\[.*?\]', '', line)
            print(f"  Line {i+1}: {clean_line}")
            print(f"    Display length: {len(clean_line)} chars")
    
    # Show improvement
    original_length = 81  # From previous test with 16 bytes/row
    new_length = len(re.sub(r'\[.*?\]', '', lines[0])) if lines[0] else 0
    
    print(f"\n📊 Layout improvement:")
    print(f"  Original (16 bytes/row): ~{original_length} characters")
    print(f"  Improved ({hex_viewer.bytes_per_row} bytes/row): ~{new_length} characters")
    print(f"  Better utilization: {new_length > original_length}")

if __name__ == "__main__":
    test_layout()
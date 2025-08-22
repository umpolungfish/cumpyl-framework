#!/usr/bin/env python3
"""Test script to check hex viewer layout adjustments"""

from cumpyl_package.hex_viewer import HexViewer
from cumpyl_package.config import ConfigManager

def test_hex_layout():
    """Test hex viewer bytes per row calculation"""
    
    print("Testing hex viewer layout adjustments...")
    
    # Create config and hex viewer
    config = ConfigManager()
    hex_viewer = HexViewer(config)
    
    # Load a test file
    try:
        hex_viewer.load_from_file('4dglasses.exe')
        print(f"✓ Loaded file: {hex_viewer.file_path}")
        print(f"  File size: {hex_viewer.file_size:,} bytes")
        print(f"  Initial bytes_per_row: {hex_viewer.bytes_per_row}")
        
        # Simulate the TextualHexViewer width adjustment
        if hasattr(hex_viewer, '_adjust_bytes_per_row'):
            print("\n[INFO] hex_viewer doesn't have _adjust_bytes_per_row method")
        else:
            print("\n[INFO] Simulating TextualHexViewer width adjustment...")
            
            # Simulate different terminal widths
            test_widths = [80, 120, 144, 180, 200]
            
            for width in test_widths:
                # Simulate the calculation from _adjust_bytes_per_row
                terminal_width = width
                if terminal_width <= 80:
                    terminal_width = 144
                
                overhead = 15
                chars_per_byte = 4.125
                available_width = terminal_width - overhead
                raw_bytes_estimate = int(available_width / chars_per_byte)
                new_bytes_per_row = (raw_bytes_estimate // 8) * 8
                
                if new_bytes_per_row < 8:
                    new_bytes_per_row = 8
                elif new_bytes_per_row > 64:
                    new_bytes_per_row = 64
                    
                if new_bytes_per_row <= 16 and terminal_width > 100:
                    new_bytes_per_row = 24
                
                print(f"  Terminal width {width:3d} → bytes_per_row: {new_bytes_per_row:2d}")
        
        # Generate a sample hex view with current settings
        print(f"\nGenerating sample hex view with {hex_viewer.bytes_per_row} bytes per row:")
        sample_content = hex_viewer.generate_textual_hex_view(max_bytes=hex_viewer.bytes_per_row * 3)
        lines = sample_content.split('\n')[:3]  # Show first 3 lines
        
        for i, line in enumerate(lines):
            if line.strip():
                # Remove ANSI color codes for cleaner display
                import re
                clean_line = re.sub(r'\[.*?\]', '', line)
                print(f"  Line {i+1}: {clean_line}")
                print(f"    Length: {len(clean_line)} characters")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_hex_layout()
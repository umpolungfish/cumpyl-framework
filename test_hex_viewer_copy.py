#!/usr/bin/env python3
"""
𐑑𐑧𐑕𐑑 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼 𐑒𐑩𐑐𐑦 𐑓𐑳𐑙𐑒𐑖𐑩𐑯𐑨𐑤𐑦𐑑𐑦

This script demonstrates the new copy current byte functionality 
in the Cumpyl textual hex viewer.

New keyboard shortcuts added:
- c: Copy current byte value to clipboard
- left/h: Move cursor left  
- right/l: Move cursor right

Usage:
    python test_hex_viewer_copy.py [binary_file]
    
If no file is provided, creates a small test binary.
"""

import os
import sys
import tempfile

def create_test_binary():
    """𐑒𐑮𐑦𐑱𐑑 𐑩 𐑕𐑥𐑷𐑤 𐑑𐑧𐑕𐑑 𐑚𐑲𐑯𐑩𐑮𐑦 𐑓𐑲𐑤"""
    test_data = b"CUMPYL\x00\x01\x02\x03\x04\x05Hello World!\xFF\xFE\xFD\xFC"
    
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.bin')
    temp_file.write(test_data)
    temp_file.close()
    
    print(f"Created test binary: {temp_file.name}")
    print(f"Test data: {test_data.hex()}")
    return temp_file.name

def main():
    # 𐑗𐑧𐑒 𐑦𐑓 𐑩 𐑓𐑲𐑤 𐑢𐑩𐑟 𐑐𐑮𐑩𐑝𐑲𐑛𐑦𐑛
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}")
            sys.exit(1)
    else:
        file_path = create_test_binary()
    
    # 𐑦𐑥𐑐𐑪𐑮𐑑 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼 𐑦𐑯 𐑞 ℌ
    try:
        from cumpyl_package.hex_viewer import launch_textual_hex_viewer
        
        print("\n🔥 CUMPYL Interactive Hex Viewer Test")
        print("==========================================")
        print("New keyboard shortcuts:")
        print("  c         - Copy current byte to clipboard")
        print("  left/h    - Move cursor left")
        print("  right/l   - Move cursor right")
        print("  j/down    - Scroll down")
        print("  k/up      - Scroll up")
        print("  g         - Go to top")
        print("  G         - Go to bottom")
        print("  f/        - Search")
        print("  n/N       - Next/Previous search result")
        print("  a         - Show annotation info")
        print("  r         - Refresh display")
        print("  q         - Quit")
        print("==========================================")
        print(f"Loading: {file_path}")
        print("Press 'c' to copy the current byte highlighted in blue!")
        print()
        
        # 𐑤𐑷𐑯𐑗 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼
        launch_textual_hex_viewer(file_path)
        
    except ImportError as e:
        print(f"Error: {e}")
        print("Make sure the textual package is installed: pip install textual")
        sys.exit(1)
    except Exception as e:
        print(f"Error launching hex viewer: {e}")
        sys.exit(1)
    finally:
        # 𐑒𐑤𐑰𐑯 𐑳𐑐 𐑦𐑓 𐑢𐑰 𐑒𐑮𐑦𐑱𐑑𐑦𐑛 𐑩 𐑑𐑧𐑕𐑑 𐑓𐑲𐑤
        if len(sys.argv) <= 1 and os.path.exists(file_path):
            os.unlink(file_path)
            print(f"Cleaned up test file: {file_path}")

if __name__ == "__main__":
    main()
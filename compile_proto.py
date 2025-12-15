#!/usr/bin/env python3
"""
Compile protobuf for Python usage.
This script generates a Python module from usb_comm.proto without nanopb dependencies.
"""

import subprocess
import sys
import os
import shutil

def main():
    proto_dir = "config/proto"
    proto_file = "usb_comm.proto"
    proto_path = os.path.join(proto_dir, proto_file)
    
    # Check if protoc is available
    if shutil.which("protoc") is None:
        print("Error: 'protoc' compiler not found.")
        print("Please install Protocol Buffers compiler:")
        print("  Download from: https://github.com/protocolbuffers/protobuf/releases")
        print("  and add 'bin' directory to PATH.")
        sys.exit(1)
    
    # Read the original proto file
    with open(proto_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create a temporary version without nanopb import
    temp_proto = proto_file.replace('.proto', '_temp.proto')
    temp_path = os.path.join(proto_dir, temp_proto)
    
    # Remove nanopb import and options
    lines = content.split('\n')
    filtered_lines = []
    skip_next = False
    
    for line in lines:
        # Skip nanopb import
        if 'import "nanopb.proto"' in line:
            continue
        # Skip nanopb options
        if 'nanopb_msgopt' in line or 'nanopb_enumopt' in line or 'nanopb_fileopt' in line:
            skip_next = True
            continue
        if skip_next and line.strip() == '':
            skip_next = False
            continue
        if skip_next:
            continue
            
        filtered_lines.append(line)
    
    # Write temporary file
    with open(temp_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(filtered_lines))
    
    try:
        # Compile the temporary proto file
        cmd = [
            "protoc",
            f"-I={proto_dir}",
            "--python_out=.",
            temp_path
        ]
        
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error compiling protobuf:")
            print(result.stderr)
            sys.exit(1)
        
        # Rename the output file
        temp_output = temp_proto.replace('.proto', '_pb2.py')
        final_output = proto_file.replace('.proto', '_pb2.py')
        
        if os.path.exists(temp_output):
            if os.path.exists(final_output):
                os.remove(final_output)
            os.rename(temp_output, final_output)
        
        print(f"Successfully compiled {proto_file} -> {final_output}")
        
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == "__main__":
    main()

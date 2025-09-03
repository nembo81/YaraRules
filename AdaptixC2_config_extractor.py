import sys
import argparse
import io
import struct
import pefile
from Crypto.Cipher import ARC4

def rc4_decrypt(key, data):
    """
    Decrypts data using the RC4 algorithm.
    """
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def find_last_nonzero_byte_index(data, search_before_index):
    """
    Searches backwards from a given index to find the first byte that is not 0x00.
    """
    for i in range(search_before_index - 1, -1, -1):
        if data[i] != 0x00:
            return i
    return -1

def parse_decrypted_config(data):
    """
    Parses the decrypted config using a corrected approach
    that properly handles the data structure.
    """
    config = {}
    try:
        stream = io.BytesIO(data)
        
        # 1. Skip the 9-byte header.
        stream.seek(9)

        # 2. Read C2 Server (format: [Length][Value including null])
        c2_len = struct.unpack('<I', stream.read(4))[0]
        c2_data = stream.read(c2_len)
        c2_val = c2_data.rstrip(b'\x00').decode('latin-1', errors='ignore')
        config['C2 Server'] = c2_val

        # 3. Skip the 4-byte intermediate "type" field (e.g., bb 01 00 00).
        stream.read(4)

        # 4. Read Method field
        method_len = struct.unpack('<I', stream.read(4))[0]
        method_data = stream.read(method_len)
        method_val = method_data.rstrip(b'\x00').decode('latin-1', errors='ignore')
        config['Method'] = method_val

        # 5. Read Path field
        path_len = struct.unpack('<I', stream.read(4))[0]
        path_data = stream.read(path_len)
        path_val = path_data.rstrip(b'\x00').decode('latin-1', errors='ignore')
        config['Path'] = path_val
        
        # 6. Read Header Name field
        h_name_len = struct.unpack('<I', stream.read(4))[0]
        header_data = stream.read(h_name_len)
        header_name = header_data.rstrip(b'\x00').decode('latin-1', errors='ignore')
        config['Header Name'] = header_name

        # 7. Read User-Agent field
        ua_len = struct.unpack('<I', stream.read(4))[0]
        ua_data = stream.read(ua_len)
        ua_val = ua_data.rstrip(b'\x00').decode('latin-1', errors='ignore')
        config['User-Agent'] = ua_val

        return config

    except (struct.error, IndexError) as e:
        # This handles cases where the config is shorter or malformed
        print(f"[!] Warning: Parsing stopped early due to: {e}", file=sys.stderr)
        return config
    except Exception as e:
        print(f"[!] Warning: An error occurred during parsing: {e}", file=sys.stderr)
        return config

def analyze_pe_file(filepath):
    """
    Main function to analyze the PE file, extract, decrypt, and parse the config.
    """
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError as e:
        print(f"[!] ERROR: Not a valid PE file. {e}", file=sys.stderr)
        return
    except FileNotFoundError:
        print(f"[!] ERROR: File not found at '{filepath}'", file=sys.stderr)
        return

    rdata_section = None
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == '.rdata':
            rdata_section = section
            break
    if not rdata_section: 
        print("[!] ERROR: .rdata section not found", file=sys.stderr)
        return

    rdata = rdata_section.get_data()
    marker = b'Undefined symbol'
    marker_index = rdata.find(marker)
    if marker_index == -1:
        print("[!] ERROR: Marker 'Undefined symbol' not found", file=sys.stderr)
        return

    block_end_index = find_last_nonzero_byte_index(rdata, marker_index)
    if block_end_index == -1:
        print("[!] ERROR: Could not find end of data block", file=sys.stderr)
        return
        
    key_size = 16
    key_start_index = (block_end_index + 1) - key_size
    rc4_key = rdata[key_start_index : block_end_index + 1]
    data_start_offset = 4
    encrypted_data = rdata[data_start_offset:key_start_index]

    try:
        decrypted_data = rc4_decrypt(rc4_key, encrypted_data)
        parsed_config = parse_decrypted_config(decrypted_data)
        
        if parsed_config:
            print("-" * 50)
            print("Extracted AdaptixC2 Configuration:")
            print("-" * 50)
            for key, value in parsed_config.items():
                if value and value.strip():  # Only show non-empty values
                    print(f"  {key:<15}: {value}")
            print("-" * 50)
        else:
            print("[!] Could not parse configuration.", file=sys.stderr)

    except Exception as e:
        print(f"[!] An error occurred during decryption or analysis: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="Extracts and parses encrypted configuration from AdaptixC2 PE files.")
    parser.add_argument("filepath", help="Path to the PE file to analyze.")
    args = parser.parse_args()
    
    analyze_pe_file(args.filepath)

if __name__ == "__main__":
    main()

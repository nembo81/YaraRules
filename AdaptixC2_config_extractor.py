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

def parse_decrypted_config_sequential(data):
    """
    Parses the decrypted config by reading fields sequentially,
    adaptively handling an optional intermediate field.
    """
    config = {}
    try:
        stream = io.BytesIO(data)
        stream.seek(9)

        c2_len_bytes = stream.read(4)
        if len(c2_len_bytes) < 4: return config
        c2_len = struct.unpack('<I', c2_len_bytes)[0]
        c2_val = stream.read(c2_len).decode('latin-1', errors='ignore')
        stream.read(1)
        config['C2 Server'] = c2_val

        # The rest of the fields are still parsed to ensure the structure is valid,
        # but they are not used for the final output.
        next_four_bytes = stream.read(4)
        optional_intermediate_id = b'\xbb\x01\x00\x00'
        if next_four_bytes != optional_intermediate_id:
            stream.seek(-4, io.SEEK_CUR)
        
        if len(next_four_bytes) < 4:
            return config

        method_len = struct.unpack('<I', stream.read(4))[0]
        stream.read(method_len)

        path_len = struct.unpack('<I', stream.read(4))[0]
        stream.read(path_len)
        
        h_name_len = struct.unpack('<I', stream.read(4))[0]
        stream.read(h_name_len)

        ua_len = struct.unpack('<I', stream.read(4))[0]
        stream.read(ua_len)

        return config

    except (struct.error, IndexError):
        return config
    except Exception:
        return config

def analyze_pe_file(filepath):
    """
    Main function to analyze the PE file, extract, decrypt, and parse the config.
    Prints "C2: <value>" on success.
    """
    try:
        pe = pefile.PE(filepath)
    except (pefile.PEFormatError, FileNotFoundError):
        return

    rdata_section = None
    for section in pe.sections:
        if section.Name.decode().strip('\x00') == '.rdata':
            rdata_section = section
            break
    if not rdata_section: return

    rdata = rdata_section.get_data()

    marker = b'Undefined symbol'
    marker_index = rdata.find(marker)
    if marker_index == -1: return

    block_end_index = find_last_nonzero_byte_index(rdata, marker_index)
    if block_end_index == -1: return
        
    key_size = 16
    key_start_index = (block_end_index + 1) - key_size
    rc4_key = rdata[key_start_index : block_end_index + 1]

    data_start_offset = 4
    encrypted_data = rdata[data_start_offset:key_start_index]

    try:
        decrypted_data = rc4_decrypt(rc4_key, encrypted_data)
        parsed_config = parse_decrypted_config_sequential(decrypted_data)
        
        if parsed_config and 'C2 Server' in parsed_config:
            # --- THIS IS THE MODIFIED PRINT STATEMENT ---
            print(f"C2: {parsed_config['C2 Server']}")
        
    except Exception:
        return

def main():
    parser = argparse.ArgumentParser(description="Extracts a C2 address from a PE file's .rdata section.")
    parser.add_argument("filepath", help="Path to the PE file to analyze.")
    args = parser.parse_args()
    
    analyze_pe_file(args.filepath)

if __name__ == "__main__":
    main()
import sys
import os
import pefile
import re
from pydantic import BaseModel

class TLV(BaseModel):
    p_type: int
    parent: bool
    data: bytes | None

def searchAndParseMZ(bytes_content):
    mz_index = bytes_content.find(b"MZ")

    if mz_index == -1:
        return False

    mz_content = bytes_content[mz_index:]
    
    try:
        pe = pefile.PE(data=mz_content)
        pe_size = pe.OPTIONAL_HEADER.SizeOfImage

        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                if hasattr(debug_entry, 'entry'):
                    if hasattr(debug_entry.entry, 'PdbFileName'):
                        print(f"[+] Found PDB filename in C#: {debug_entry.entry.PdbFileName.decode('utf-8', errors='replace')}")

        if pe_size > len(mz_content):
            return mz_content[:len(mz_content)]
        else:
            return mz_content[:pe_size]

    except Exception as e:
        return False


    

def decrypt_shellcode(bytes_content, filename, parsed_resource_dir):

    # Try hardcoded 0x55 first
    trial_keys = [0x55, range(0x55), range(0x56,0x100)]
    
    for trial_key in trial_keys:

        decrypted_content = b""

        for k,v in enumerate(bytes_content):
            decrypted_content += (int(v) ^ 0x55).to_bytes(1)
    

        pe_file_content = searchAndParseMZ(decrypted_content)
        if(pe_file_content):


            out_file = os.path.join(parsed_resource_dir ,f"CSharp_{filename}_{hex(trial_key)}")
            with open(out_file, 'wb') as fd:
                fd.write(pe_file_content)


            out_file = os.path.join(parsed_resource_dir, f"shellcode_{filename}_{hex(trial_key)}")
            with open(out_file, 'wb') as fd:
                fd.write(decrypted_content)
            return
       

    


def parse_tlv( res_content, tlv_array, offset=0,):



    p_type = res_content[offset] &127
    p_isParent = res_content[offset] & 128 > 0
    offset += 1

    data_len = int.from_bytes(res_content[offset:offset+4], byteorder="little", signed=False)
    offset += 4
    

    if (p_isParent) :
        
        offset = parse_tlv(res_content, tlv_array, offset)
        object_tlv = TLV(p_type=p_type, parent=p_isParent, data=None)
        
    else :
        data = res_content[offset:offset+data_len]
        offset += data_len
        object_tlv =  TLV(p_type=p_type, parent=p_isParent, data=data)
        


    tlv_array.append(object_tlv)

    
    if (offset< len(res_content)):
        offset = parse_tlv(res_content, tlv_array, offset)

    
    return offset

def parse_c2_config(bytes_content, filename, parsed_resource_dir):
    # TODO Further parse this blob into tlv format -> based on the C# binary HostConf
    with open(os.path.join(parsed_resource_dir, f"config_{filename}"), 'wb') as fd:
        fd.write(bytes_content)




def parse_resource(filename, decrypted_resource_blob, parsed_resource_dir):
    global GLOBAL_RES_PARSER

    try:
        tlv_array = []
        parse_tlv(decrypted_resource_blob, tlv_array)

        for node in tlv_array:
            # print(f"Parent: {node.parent}, type: {node.p_type}")
            # Type 3 is shellcode
            # Type 5 is config
            if (node.p_type == 3):
                decrypt_shellcode(node.data, filename, parsed_resource_dir)

            if (node.p_type == 5):
                parse_c2_config(node.data, filename, parsed_resource_dir)
    except Exception as e:
        print(f"Error parsing shellcode/c#/config for {filename}")
        print(e)

    GLOBAL_RES_PARSER += 1


def extract_resource(exe_path, resource_id, resource_type_str):
    try:
        # Try to open as a PE file
        try:
            pe = pefile.PE(exe_path)
            
            # Convert string resource type to integer if needed
            resource_type = None
            if resource_type_str == 'TXT':
                resource_type = 10
            
            # Check if the file has a resource section
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                # First try with the string type
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    # Check both string and ID-based resources
                    if (hasattr(entry, 'name') and entry.name and 
                        hasattr(entry.name, 'string') and 
                        entry.name.string and 
                        entry.name.string.decode('utf-8', errors='ignore') == resource_type_str):
                        for entry_id in entry.directory.entries:
                            if entry_id.id == resource_id:
                                for language in entry_id.directory.entries:
                                    data_rva = language.data.struct.OffsetToData
                                    size = language.data.struct.Size
                                    data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                    return data
                
                # Try with all resource types as fallback
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for entry_id in entry.directory.entries:
                        if entry_id.id == resource_id:
                            for language in entry_id.directory.entries:
                                data_rva = language.data.struct.OffsetToData
                                size = language.data.struct.Size
                                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                print(f"Found resource {resource_id} with type {entry.id}")
                                return data
            
            return None
            
        except pefile.PEFormatError:
            # If not a valid PE file, try to read it directly
            print(f"{os.path.basename(exe_path)} is not a valid PE file. Trying direct extraction...")
            
            # Read the entire file
            with open(exe_path, 'rb') as f:
                file_data = f.read()
                
                # Try to find decryptable patterns in the data
                # This is a simplified approach - we're treating the entire file as potentially encrypted data
                print(f"Treating entire file as potential encrypted data ({len(file_data)} bytes)")
                return file_data
                
    except Exception as e:
        print(f"Error extracting resource from {os.path.basename(exe_path)}: {e}")
        return None

def decrypt_resource(input_data):
    if len(input_data) % 2 != 0:
        print("Warning: Input data length is not even, padding with 'A'")
        input_data += b'A'
    
    output_size = len(input_data) // 2
    output_data = bytearray(output_size)
    
    for i in range(0, len(input_data), 2):
        first_byte = input_data[i]
        second_byte = input_data[i + 1]
        
        # Apply the decryption formula: (second_byte - 65) | (16 * (first_byte - 65))
        decrypted_byte = (second_byte - 65) | (16 * (first_byte - 65))
        output_data[i // 2] = decrypted_byte
    
    return output_data

def find_byte_pattern(data):
    # Define the pattern to search for
    pattern = bytes([0x96, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55])
    
    # Find the pattern in the data
    offset = data.find(pattern)
    
    if offset == -1:
        print("Pattern not found in the data.")
        return None
    
    print(f"Pattern found at offset: {offset} (0x{offset:X})")
    return offset

def find_network_indicators(data):
    # Convert bytearray to string (assuming ASCII/UTF-8 encoding)
    # We'll use errors='replace' to handle non-printable characters
    data_str = data.decode('utf-8', errors='replace')
    
    # Regular expression patterns
    patterns = {
        # IPv4 pattern
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        
        # IPv6 pattern (handles various IPv6 formats)
        'ipv6': r'(?:^|[^\w:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))',
        
        # URL pattern (matches common URL formats)
        'url': r'(?:https?://|www\.)[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=]*)?|[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}',
        
        # Domain pattern (simplified, might need adjustment based on your needs)
        'domain': r'\b[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\b'
    }
    
    results = {}
    
    for indicator_type, pattern in patterns.items():
        matches = re.findall(pattern, data_str)
        if matches:
            results[indicator_type] = list(set(matches))

    return results

def process_file(exe_path, resource_id, resource_type, output_dir=None):
    print(f"\n{'='*50}")
    print(f"Processing: {exe_path}")
    print(f"{'='*50}")
    
    if not os.path.exists(exe_path):
        print(f"Error: File {exe_path} not found.")
        return False
    
    try:
        # Skip files that are too small (less than 10 bytes)
        file_size = os.path.getsize(exe_path)
        if file_size < 10:
            print(f"Skipping {os.path.basename(exe_path)}: File too small ({file_size} bytes)")
            return False
        
        # Create output directories
        if output_dir:
            # Create main output directory
            os.makedirs(output_dir, exist_ok=True)
            
            # Create subdirectories for different output types
            encrypted_dir = os.path.join(output_dir, "encrypted_res")
            decrypted_dir = os.path.join(output_dir, "decrypted_res")
            iocs_dir = os.path.join(output_dir, "IoCs")
            parsed_resource_dir = os.path.join(output_dir, "parsed_shellcode")
            
            os.makedirs(encrypted_dir, exist_ok=True)
            os.makedirs(decrypted_dir, exist_ok=True)
            os.makedirs(iocs_dir, exist_ok=True)
            os.makedirs(parsed_resource_dir, exist_ok=True)
            
            # Set filenames with proper paths
            filename_base = os.path.basename(exe_path)
            encrypted_res_name = os.path.join(encrypted_dir, f"{filename_base}.bin")
            decrypted_res_name = os.path.join(decrypted_dir, f"{filename_base}.bin")
            indicators_name = os.path.join(iocs_dir, f"{filename_base}.txt")
        else:
            # Use current directory structure if no output dir specified
            base_dir = os.path.dirname(exe_path) or "."
            
            # Create subdirectories for different output types
            encrypted_dir = os.path.join(base_dir, "encrypted_res")
            decrypted_dir = os.path.join(base_dir, "decrypted_res")
            iocs_dir = os.path.join(base_dir, "IoCs")
            parsed_resource_dir = os.path.join(base_dir, "parsed_shellcode")
            
            os.makedirs(encrypted_dir, exist_ok=True)
            os.makedirs(decrypted_dir, exist_ok=True)
            os.makedirs(iocs_dir, exist_ok=True)
            os.makedirs(parsed_resource_dir, exist_ok=True)
            
            # Set filenames with proper paths
            filename_base = os.path.basename(exe_path)
            encrypted_res_name = os.path.join(encrypted_dir, f"{filename_base}.bin")
            decrypted_res_name = os.path.join(decrypted_dir, f"{filename_base}.bin")
            indicators_name = os.path.join(iocs_dir, f"{filename_base}.txt")
        
        # Extract the resource
        print(f"Attempting to extract data from {os.path.basename(exe_path)}...")
        resource_data = extract_resource(exe_path, resource_id, resource_type)
        
        if not resource_data:
            print(f"Error: Could not extract data from {os.path.basename(exe_path)}.")
            return False
        
        # Write the original (encrypted) data
        with open(encrypted_res_name, "wb") as f:
            f.write(resource_data)
        
        print(f"Original data size: {len(resource_data)} bytes")
        print(f"Written to: {encrypted_res_name}")
        
        # Try to decrypt the data
        try:
            decrypted_data = decrypt_resource(resource_data)
            
            # Write the decrypted data
            with open(decrypted_res_name, "wb") as f:
                f.write(decrypted_data)
            
            print(f"Decrypted data size: {len(decrypted_data)} bytes")
            print(f"Written to: {decrypted_res_name}")
            
            # Try to find the byte pattern
            config_offset = find_byte_pattern(decrypted_data)
            
            if config_offset is not None:
                # Extract everything after the offset
                config = decrypted_data[config_offset:]
                
                # Extract and write indicators to file
                results = find_network_indicators(config)
                if results:
                    with open(indicators_name, "w") as f:
                        f.write(f"Network indicators found in {os.path.basename(exe_path)}:\n\n")
                        for indicator_type, matches in results.items():
                            f.write(f"\n{indicator_type.upper()} indicators found ({len(matches)}):\n")
                            for match in matches:
                                f.write(f"{match}\n")
                    
                    # Print results
                    print("\nNetwork indicators found:")
                    for indicator_type, matches in results.items():
                        print(f"\n{indicator_type.upper()} indicators found ({len(matches)}):")
                        for i, match in enumerate(matches, 1):
                            print(f"{match}")
                    print(f"\nIndicators written to: {indicators_name}")
                else:
                    print("No network indicators found in the decrypted data.")
            else:
                # Even if pattern not found, still try to find network indicators in the entire decrypted data
                print("Standard pattern not found, scanning entire decrypted data for indicators...")
                results = find_network_indicators(decrypted_data)
                if results:
                    with open(indicators_name, "w") as f:
                        f.write(f"Network indicators found in {os.path.basename(exe_path)} (full scan):\n\n")
                        for indicator_type, matches in results.items():
                            f.write(f"\n{indicator_type.upper()} indicators found ({len(matches)}):\n")
                            for match in matches:
                                f.write(f"{match}\n")
                    
                    print("\nNetwork indicators found (full scan):")
                    for indicator_type, matches in results.items():
                        print(f"\n{indicator_type.upper()} indicators found ({len(matches)}):")
                        for i, match in enumerate(matches, 1):
                            print(f"{match}")
                    print(f"\nIndicators written to: {indicators_name}")
                else:
                    print("No network indicators found in the entire decrypted data.")
                
        except Exception as e:
            print(f"Error during decryption or analysis: {e}")
            print("The file was extracted but could not be properly decrypted or analyzed.")
            return False
        
        
        # Parse resources here
        filename = os.path.basename(exe_path)

        
        parse_resource(filename, decrypted_data, parsed_resource_dir)

        return True
    
    except Exception as e:
        print(f"Error processing {os.path.basename(exe_path)}: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Process single file: python tuoni_config_extractor.py <path_to_exe>")
        print("  Process directory:   python tuoni_config_extractor.py --dir <directory_path> [--output <output_directory>]")
        return
    
    resource_id = 104
    resource_type = 'TXT'
    
    # Check if processing a directory
    if sys.argv[1] == "--dir":
        if len(sys.argv) < 3:
            print("Error: Directory path not specified.")
            return
        
        dir_path = sys.argv[2]
        
        # Check for output directory parameter
        output_dir = None
        if len(sys.argv) > 3 and sys.argv[3] == "--output" and len(sys.argv) > 4:
            output_dir = sys.argv[4]
        
        if not os.path.isdir(dir_path):
            print(f"Error: {dir_path} is not a valid directory.")
            return
        
        print(f"Scanning directory: {dir_path}")
        print(f"Output directory: {output_dir if output_dir else 'Subdirectories within scan directory'}")
        
        # Get all files in directory
        files = [os.path.join(dir_path, f) for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
        
        print(f"Found {len(files)} files to process.")
        
        # Process each file
        success_count = 0
        for i, file_path in enumerate(files, 1):
            print(f"\nProcessing file {i}/{len(files)}: {os.path.basename(file_path)}")
            if process_file(file_path, resource_id, resource_type, output_dir):
                success_count += 1
        
        print(f"\nProcessing complete. Successfully processed {success_count} out of {len(files)} files.")
    
    else:
        # Process single file
        exe_path = sys.argv[1]
        process_file(exe_path, resource_id, resource_type)

if __name__ == "__main__":
    main()

## Tuoni Config Extractor
A Python tool that extracts and decrypt configuration data from unpacked Tuoni Windows binary samples.

### Description
This tool analyzes PE (Portable Executable) files that are potentially Tuoni malware, extracting encrypted configuration data from resources, decrypting it using a known algorithm, and identifying network indicators such as IPs, domains, and URLs. Works for Tunoi version 0.9.1 and below 

### Features
- Extract resources from PE files
- Decrypt Tuoni-encrypted configuration data
- Identify and extract network indicators (IPs, URLs, domains) using regex
- Process individual files or entire directories
- Save extracted data to organized output directories

### Usage
- Processes a single file
```
python tunoi_config_extractor.py <path_to_exe>
```
- Process an entire directory:
```
python tunoi_config_extractor.py --dir <directory_path> [--output <output_directory>]
```
- Default output directory
```
<output_directory>/
  ├── encrypted_res/  # Original encrypted resources
  ├── decrypted_res/  # Decrypted configuration data
  └── IoCs/    
```
def convert_patch_line(line):
    if not line.strip() or line.startswith(">"):
        return None
    
    parts = line.split(":")
    if len(parts) != 2:
        return None
    
    offset_hex = parts[0].strip()
    byte_change = parts[1].strip()
    
    if "->" in byte_change:
        original_byte_hex, new_byte_hex = byte_change.split("->")
    else:
        original_byte_hex = byte_change
        new_byte_hex = original_byte_hex
    
    offset_dec = int(offset_hex, 16)
    original_byte_dec = int(original_byte_hex, 16)
    new_byte_dec = int(new_byte_hex, 16)
    
    return f"{offset_dec}, {original_byte_dec}, {new_byte_dec}"

def main():
    input_file = "patch.1337"
    output_file = "pastebin.txt"
    
    with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
        for line in f_in:
            if line.startswith(">"):
                process_name = line[1:].strip()
                f_out.write(f"process: {process_name}\n")
                f_out.write(f"module: {process_name}\n\n")
                f_out.write("decimal:\n")
                continue
            
            converted = convert_patch_line(line)
            if converted:
                f_out.write(converted + "\n")
    
    print(f"Converted patches saved to: {output_file}")

if __name__ == "__main__":
    main()
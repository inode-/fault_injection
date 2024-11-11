
import struct
import subprocess
import re
import binascii

# List of instructions to parse and analyze
instruction_list = [b"\x62\xC6\x01", b"\x62\xC6\x02", b"\x62\xC6\x04", b"\x62\xC6\x08", b"\x62\xC6\x10", b"\x62\xC6\x20", b"\x62\xC6\x40"]

# Path to the 'xtensa-esp32-elf-objdump' binary, used for disassembly of opcodes
xtensa_objdump = "xtensa-esp32-elf-objdump"

def diffcolor(original, new, start, len):
    """
    Generates a color-coded string to visually indicate differences between two strings.

    Parameters:
    - original: The original string.
    - new: The modified string.
    - start: The starting index for comparison.
    - len: The number of characters to compare.
    """
    original = original[::-1]
    new = new[::-1]

    s = new[0:start]
    for i in range(start, start + len):
        if original[i] == new[i]:
            s += 'm0[\033' + new[i] + 'm29[\033'
        else:
            s += 'm0[\033' + new[i] + 'm19[\033'
    s += 'm0[\033' + new[start + len:]
    
    return s[::-1]

def xtensa_disassemble(opcode):
    """
    Disassembles the given opcode using the external tool 'xtensa-esp32-elf-objdump'.

    Parameters:
    - opcode: The opcode to disassemble.

    Returns:
    - The disassembled instruction as a string.
    """
    buffer = struct.pack("<I", opcode)
    with open("xtensa_disassemble.txt", "wb") as f:
        f.write(buffer[:-1])

    out = subprocess.run([xtensa_objdump, "-D", "-m", "xtensa", "-b", "binary", "xtensa_disassemble.txt"], capture_output=True)

    # Reverse the opcode bytes and convert to hex for matching
    op = hex(struct.unpack(">I", buffer)[0])[2:-2]
    x = re.search(".*" + str(op) + " *(.*)", str(out.stdout.decode('utf-8')))
    return x.group(1)

def bit_flip(number, max_bit, number_of_bits, reduct=0):
    """
    Performs bit-flip operations on the input number, printing results in a formatted table.

    Parameters:
    - number: The binary instruction.
    - max_bit: Maximum number of bits to flip.
    - number_of_bits: Total number of bits in the opcode.
    - reduct: Optional flag to skip already calculated results.
    """
    res = []
    
    number += b'\x00'
    number = struct.unpack("<I", number)[0]

    print("Instruction:\n" + str(hex(number)) + ' - ' + str(format(number, '#0' + str(number_of_bits + 2) + 'b')) + ' - ' + xtensa_disassemble(number))

    orig = format(number, '0' + str(number_of_bits) + 'b')

    # Loop through bits to flip
    for n_bit in range(1, max_bit + 1):
        bit_to_flip = sum((1 << i) for i in range(n_bit))

        print('Bit to flip: ' + str(hex(bit_to_flip)))

        for i in range(number_of_bits - n_bit + 1):
            to_flip = bit_to_flip << i

            # Convert to binary and flip bits
            x = format(to_flip, '0' + str(number_of_bits) + 'b').replace('1', '2').replace('0', '1').replace('2', '0')
            opposite = int(x, 2)
            number_op = number
            x = number_op & opposite

            # If reduction flag is on, skip duplicates
            if reduct == 1:
                if any(h[0] == x for h in res):
                    continue

            if number == x:
                continue

            res.append((x, i, n_bit))

    # Output results in a formatted table
    print("+----------+-----------------------------+-----------------------+")
    print("|   Opcode | Bit representation          | Assembler             |")
    print("+----------+-----------------------------+-----------------------+")

    padded_opc = '{: >9}'.format(format(number, '#0' + str(8) + 'x')[2:])
    print("┃" + padded_opc + " ┃ " + str(format(number, '#0' + str(number_of_bits + 2) + 'b'))[2:].ljust(27) + " ┃ " + xtensa_disassemble(number)[1:] + "\t ┃ ")

    # Display each flipped result
    for x in res:
        cur = format(x[0], '0' + str(number_of_bits) + 'b')
        padded_opc = '{: >9}'.format(format(x[0], '#0' + str(8) + 'x')[2:])
        print("┃" + padded_opc + " ┃ " + diffcolor(orig, cur, x[1], x[2]).ljust(27) + " ┃ " + xtensa_disassemble(x[0])[1:] + "\t ┃ ")
        
    print("+----------+-----------------------------+-----------------------+")

    # Prepare flipped opcodes in Java-compatible format
    to_java = str(format(struct.unpack(">I", struct.pack("<I", number))[0], '#0' + str(8) + 'x'))[:-2] + 'L'
    to_java += ', '.join(', ' + str(format(struct.unpack(">I", struct.pack("<I", x[0]))[0], '#0' + str(8) + 'x'))[:-2] + 'L' for x in res)
    print(to_java)

# Execute bit flipping on each instruction in the list
for j in instruction_list:
    bit_flip(j, 3, 24, 1)
    print('-----')

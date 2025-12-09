The challenge presented a stripped 64-bit ELF executable named `chal`.
Upon execution, it prompted for a password:

```
I heard that you got some crazy vault breaking skills

Try to break this one

Enter the password:
```

Initial attempts with arbitrary input resulted in:

```
L00ks like you got some real skill issue.
Better luck next time.
```

Analysis using `objdump -d chal` and `readelf -S chal` revealed the following:

1.  **Password Length:** The `main` function (at `0x1460`) used `scanf` to read input and then checked its length using `strcspn`. It compared the length against `0x35` (decimal 53). If the length was not 53, it printed the "skill issue" message and exited. This established the password length as 53 characters.

2.  **Dynamic Code Generation (JIT):**
    The core validation logic was found in a function called by `main` (at `0x1379`). This function iterated 53 times (once for each character of the password). In each iteration, it performed the following:
    *   It called another function (at `0x1249`) to dynamically generate a small piece of executable code (shellcode).
    *   This dynamically generated shellcode was then executed to validate the current character of the password.
    *   The address of the generated shellcode (in a memory-mapped executable region) was passed via `%r9`.

3.  **Shellcode Generation Logic (Function at `0x1249`):**
    This function was responsible for "decrypting" the validation logic for each password character.
    *   It allocated a 56-byte executable memory region using `mmap`.
    *   It iterated 56 times, reading an encrypted byte `B` from a `data` section (`0x4020 + 57 * i + j`).
    *   It XORed `B` with a 4-byte key `K` (read from `0x4c00 + i * 4`). Specifically, it used the lowest byte of the XOR operation `(B ^ K) & 0xFF` to reconstruct the shellcode byte. This means `K` was effectively used as a single-byte XOR key for decryption, repeating for each byte of the shellcode.
    *   The decrypted bytes formed the actual machine code for the character's validation function.

4.  **Shellcode Validation Logic:**
    Disassembly of the generated shellcode (e.g., `func_0.bin`) revealed a consistent structure:
    *   `mov $SHIFT, %ecx`: The first instruction loaded a varying `SHIFT` value into `%ecx`. This `SHIFT` determined the starting bit position for validation.
    *   `xor %rsi, %rdi`: The input character (`%rdi`) was XORed with the full 4-byte key (`%rsi`, passed from the main loop, which was `K`). Let `Y = input_char ^ K`.
    *   A loop then iterated 8 times (for bits 0-7). In each iteration `k` (0 to 7):
        *   It extracted a specific bit from `Y`: `bit = (Y >> ((SHIFT + k) % 8)) & 1`.
        *   This `bit` was compared against an `expected_bit` value. The `expected_bit` was read from a `bits` section (`0x4ce0 + i * 32 + k * 4`).
        *   If all 8 bits matched, the shellcode returned 1 (success); otherwise, it returned 0 (failure).

5.  **Reconstruction Algorithm:**
    To find the password, for each character `i` from 0 to 52:
    *   **Get Key:** Read the 4-byte key `K` from `0x4c00 + i * 4`.
    *   **Get Shift:** Decrypt the first two bytes of the `i`-th shellcode. The second byte `b1` of the decrypted code (`data[0x3020 + 57*i + 1] ^ (K & 0xFF)`) yielded the `SHIFT` value.
    *   **Reconstruct Y:** Initialize `Y = 0`. For `k` from 0 to 7:
        *   Read `expected_bit` from `0x4ce0 + i * 32 + k * 4`.
        *   Calculate the bit position: `bit_pos = (SHIFT + k) % 8`.
        *   If `expected_bit` is 1, set the `bit_pos` bit in `Y`.
    *   **Derive Character:** Since `Y = input_char ^ K`, then `input_char = Y ^ K`. As only the lower 8 bits were relevant (`Y` was an 8-bit value), the actual character was `chr(Y ^ (K & 0xFF))`.

The Python script `solve_final_v2.py` implemented this logic.

**Python Script (`solve_final_v2.py`):**

```python
import struct

def solve():
    with open('chal', 'rb') as f:
        data = f.read()

    # Offsets (determined from readelf -S chal)
    # 0x4020 (data_section_offset) is relative to its containing .data section (0x3000 file offset)
    # 0x4c00 (key_section_address) -> 0x3c00 (file offset)
    # 0x4ce0 (bits_section_address) -> 0x3ce0 (file offset)
    data_section_offset = 0x3020
    key_section_offset = 0x3c00
    bits_section_offset = 0x3ce0

    password = []

    for i in range(53):
        # 1. Read Key (used as XOR key in the check function)
        key_offset = key_section_offset + (i * 4)
        key_bytes = data[key_offset:key_offset+4]
        key = struct.unpack('<I', key_bytes)[0] # Keys are 4-byte little endian integers
        
        # 2. Decrypt the first two bytes of the shellcode to find 'start_shift'
        # The instruction is 'b9 SHIFT 00 00 00' (mov $SHIFT, %ecx)
        # Encrypted byte 0: data[data_section_offset + 57*i + 0]
        # Encrypted byte 1: data[data_section_offset + 57*i + 1]
        
        enc_b0 = data[data_section_offset + 57*i + 0]
        enc_b1 = data[data_section_offset + 57*i + 1]
        
        dec_b0 = enc_b0 ^ (key & 0xFF) # The lowest byte of the key is used for shellcode decryption
        dec_b1 = enc_b1 ^ (key & 0xFF)
        
        if dec_b0 != 0xB9:
            print(f"Error: Func {i} does not start with 0xB9 (mov %ecx). Found {hex(dec_b0)}")
            # Fallback to default if there's an unexpected format, though this indicates an issue.
            start_shift = 4 
        else:
            start_shift = dec_b1
            
        # 3. Reconstruct Y = char ^ K (where K is the actual 4-byte key)
        # The character's bits are checked in the order: (start_shift + k) % 8 for k = 0 to 7.
        
        Y = 0 # This will hold the 8-bit value of (char ^ K)
        base_bits_offset = bits_section_offset + (i * 32)
        
        for k in range(8):
            # The expected bit is stored as a single byte at base_bits_offset + (k * 4)
            expected_bit_offset = base_bits_offset + (k * 4)
            expected_bit = data[expected_bit_offset] # Read byte
            
            # The bit position in Y being checked in this iteration
            bit_pos = (start_shift + k) % 8
            
            if expected_bit: # If the expected bit is 1
                Y |= (1 << bit_pos) # Set that bit in Y
        
        # 4. Derive the actual character
        # We have Y = input_char ^ K. Therefore, input_char = Y ^ K.
        # Since Y is an 8-bit value, we only care about the lowest 8 bits of K.
        char_code = Y ^ (key & 0xFF)
        password.append(chr(char_code))

    print("Password:", "".join(password))

if __name__ == '__main__':
    solve()
```

**Execution:**
Running the script yielded the password:
`flag{hm_she11c0d3_v4u17_cr4ck1ng_4r3_t0ugh_r1gh7!!??}`

Verification with `./chal` confirmed the flag:
`echo "flag{hm_she11c0d3_v4u17_cr4ck1ng_4r3_t0ugh_r1gh7!!??}" | ./chal`
Output: `Good job`
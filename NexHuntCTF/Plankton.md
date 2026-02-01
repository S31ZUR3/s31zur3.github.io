Binary Exploitation
Binary Exploitation
Binary Exploitation
Binary Exploitation
Binary Exploitation
Binary Exploitation
## Challenge Overview
The challenge provides a 64-bit ELF binary `chall`.
Protections:
- NX: Likely enabled (standard).
- PIE: Likely enabled (based on leaks).
- The binary uses a custom `mmap` region with RWX permissions.

## Analysis

### 1. Format String Vulnerability (Info Leak)
The function `process_input` reads input using `fgets` into a buffer at `rbp-0x3e0` and then prints it directly using `printf(buffer)`.
This is a classic Format String vulnerability.
We can use this to leak values from the stack.
- We need the address of the RWX memory region created in `main` via `mmap`.
- We need a "key" used for the obfuscation logic.

By debugging with GDB (or trial and error), we identified:
- `%7$p`: Leaks the address of the `mmap`ed region.
- `%131$p`: Leaks a value where the MSB corresponds to the initial "key" byte used by the program.

### 2. Logic & Vulnerability
The program:
1. `mmap`s a region with RWX permissions (`PROT_READ | PROT_WRITE | PROT_EXEC`).
2. Calls `process_input` passing this mmap address.
3. `process_input` asks for a "payload (hex)".
4. It parses the hex string and stores the bytes.
5. It calls `obfuscated_copy`. This function XORs the input bytes with a pseudo-random key sequence and stores the result in a stack buffer at `rbp-0xa0`.
   - Key update logic: `key = (key * 23 + 7) & 0xFF`.
6. Finally, it `memcpy`s the content of `rbp-0xa0` to the RWX mmap region.

**The Flaw**:
The buffer `rbp-0xa0` is 160 bytes away from the saved RBP.
The program allows reading up to 255 bytes (checked via a counter at `rbp-0x8`).
Since 255 > 168 (distance to return address), we can overflow the buffer and overwrite the return address.

### 3. Obstacle: The Counter Variable
The counter variable (length of data) is located at `rbp-0x8`.
The buffer starts at `rbp-0xa0`.
The distance is `0xa0 - 0x8 = 152` bytes.
When we fill the buffer to reach the return address (offset 168), we inevitably overwrite the counter at offset 152.
If we corrupt this counter with garbage, the subsequent `memcpy` (which uses this counter as the size) might crash or copy the wrong amount of data.
**Solution**: We must overwrite the counter with the correct total length of our payload (e.g., 176 bytes).

## Exploit Strategy

1. **Leak Phase**:
   - Send `%7$p %131$p` to the first prompt.
   - Parse the `mmap` address and the initial key.

2. **Payload Construction**:
   - **Shellcode**: Standard x64 shellcode (`execve("/bin/sh", ...)`).
   - **Padding**: Fill with NOPs (`\x90`) to reach offset 152.
   - **Fix Counter**: Insert the total payload length (p64(176)) at offset 152.
   - **Padding**: Fill 8 more bytes (for saved RBP) to reach offset 168.
   - **Return Address**: Overwrite with the address of the `mmap` region.

3. **Encryption (Encoding)**:
   - Since the program XORs our input with the generated key sequence to produce the final data in memory, we must pre-XOR our payload with the *same* sequence.
   - `encoded_byte = payload_byte ^ key`
   - `key = (key * 23 + 7) & 0xFF`

4. **Sending**:
   - Convert the encoded payload to a hex string.
   - Send it.
   - The program decodes the hex, "decrypts" it (restoring our raw shellcode + ret addr), copies it to the RWX region, and returns.
   - The return address now points to the RWX region containing our shellcode.
   - **Shell!**

## Flag
`nexus{Pl4NK70n_F1nds_7h3_R3c3Ip3}`


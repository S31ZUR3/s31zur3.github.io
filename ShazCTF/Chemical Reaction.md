rev
## Initial Analysis
I started by analyzing the provided binary named `chall`.
Running the `file` command revealed it is a 64-bit ELF executable for Linux.

```bash
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, ...
```

Running the binary simply prints:
```
ShaZ CTF 2025
```

Running `strings` on the binary showed some interesting strings but no flag directly.

## Reverse Engineering
I disassembled the binary using `objdump`.

```bash
objdump -d chall
```

Looking at the disassembly, I found the `main` function (entry point `0x401040`) mostly just calls `puts`. However, looking through the code, I found an interesting function at address `0x401126` that wasn't obviously called by the main execution flow.

### The Hidden Decryption Logic
The function at `0x401126` (let's call it `decrypt_flag`) contained a loop that looked like an XOR operation:

```assembly
  40113c:       0f b6 88 20 40 40 00    movzbl 0x404020(%rax),%ecx  ; Load encrypted byte
  ...
  401150:       83 e2 07                and    $0x7,%edx            ; Modulo 8 (key length)
  ...
  401159:       0f b6 80 40 40 40 00    movzbl 0x404040(%rax),%eax  ; Load key byte
  401160:       31 c1                   xor    %eax,%ecx            ; XOR operation
```

From this assembly, I identified:
1.  **Encrypted Data:** Located at address `0x404020`.
2.  **Key:** Located at address `0x404040`.
3.  **Operation:** Simple XOR encryption.
4.  **Key Length:** 8 bytes (due to `and $0x7`).

### Data Extraction
I used `objdump -s` to inspect the data sections at those addresses:

```bash
objdump -s --start-address=0x404020 --stop-address=0x404050 chall
```

Output:
```
Contents of section .data:
 404020 30000437 12105001 13045632 1153135f  0..7..P...V2.S._
 404030 0737175e 1f3c0204 57242910 00000000  .7.^.<..W$).....
 404040 6368656d 6963616c                    chemical
```

*   **Encrypted Bytes (Hex):** `3000043712105001130456321153135f0737175e1f3c020457242910`
*   **Key (ASCII):** `chemical`

## Solution Script
I wrote a simple Python script to decrypt the flag.

```python
enc = bytes.fromhex('3000043712105001130456321153135f0737175e1f3c020457242910')
key = b'chemical'
dec = bytearray()

for i in range(len(enc)):
    dec.append(enc[i] ^ key[i % 8])

print(dec.decode())
```

**Flag:** `ShaZ{s1mpl3_x0r3d_r3v_ch4LL}`
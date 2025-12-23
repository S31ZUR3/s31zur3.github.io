## 1. Challenge Overview

The challenge presented a stripped 64-bit ELF executable named `challenge`. When executed, it prompted for a "flag" and responded with "Wrong! Try again." if an incorrect input was provided. The goal was to find the correct flag.

## 2. Initial Analysis

-   **File Type:**
    ```bash
    ls -la && file challenge
    ```
    Output confirmed it was an `ELF 64-bit LSB pie executable, x86-64, stripped`. The "stripped" nature meant function names were removed, increasing the difficulty of static analysis. "PIE" (Position-Independent Executable) indicated that addresses would be relative, requiring careful RIP-relative address calculations.

-   **Execution:**
    ```bash
    ./challenge
    ```
    Output:
    ```
    Enter the flag: 12345
    Wrong! Try again.
    ```
    This confirmed the program's basic interaction.

-   **Strings Analysis:**
    ```bash
    strings challenge | grep -i flag
    ```
    Output:
    ```
    Enter the flag:
    Correct! You got the flag!
    ```
    The presence of "Correct! You got the flag!" suggested a comparison logic within the binary that we needed to locate and understand.

## 3. Reverse Engineering - Control Flow Obfuscation

The primary challenge in static analysis was the presence of control flow obfuscation using a pattern of `je` (jump if equal) and `jne` (jump if not equal) instructions targeting the same address. This effectively created an unconditional jump but confused disassemblers and made linear analysis difficult. For example:

```assembly
    16a9:       74 03                   je     16ae
    16ab:       75 01                   jne    16ae
```
Both instructions would jump to `16ae`, making `16ae` the actual next instruction. This pattern required careful manual tracing of the control flow.

The binary also used dynamic jump targets:
1.  An address (e.g., `0x11c9`) was calculated using `lea rax, [rip + offset]`.
2.  This address was then stored in a global memory location (e.g., `mov QWORD PTR [rip+offset], rax`).
3.  Later, the value from that global memory location was loaded into a register (`mov rax, QWORD PTR [rip+offset]`).
4.  Finally, an indirect jump (`jmp rax`) was used to transfer execution to the calculated address. This made it difficult to follow the flow directly in `objdump` without careful calculation.

After tracing the obfuscated entry point (`0x10e0`) and subsequent jumps, the effective `main` function started at `0x11c9`.

## 4. Identifying RC4 Algorithm

Inside the `main` function (starting at `0x11c9` after initial setup), the following sequence of operations was identified:

-   **Prompt for Input:** The string "Enter the flag:" was printed, followed by a call to `std::getline` to read user input. The length of the input was stored in a global variable at `0x44a0`.
-   **S-box Initialization (KSA Phase 1):** A loop from `0` to `255` initialized a 256-byte array (likely the S-box for RC4) with `S[i] = i`. This array was located in the `.bss` section (uninitialized data), eventually mapped to virtual address `0x4280`.
-   **Key Scheduling Algorithm (KSA Phase 2):** A second loop (from `i=0` to `255`) performed the key-dependent scrambling of the S-box. The logic closely matched the standard RC4 KSA:
    ```
    j = (j + S[i] + key_byte) % 256
    swap(S[i], S[j])
    ```
-   **Pseudo-Random Generation Algorithm (PRGA):** After the KSA, a third loop iterated for the length of the user's input. In each iteration, it generated a keystream byte and XORed it with a byte of the user's input. The standard RC4 PRGA was identified:
    ```
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    swap(S[i], S[j])
    K = S[(S[i] + S[j]) % 256]
    encrypted_input_byte = input_byte ^ K
    ```
    The results of this XOR operation (the "encrypted" user input) were stored in a buffer at `0x4420`.
-   **Comparison:** Finally, the "encrypted" user input (from `0x4420`) was compared byte-by-byte with a pre-stored ciphertext.
    -   If all bytes matched, the program jumped to a block that printed "Correct! You got the flag!" (identified by tracing a `lea` instruction to `0x20a1` in `.rodata`).
    -   If any byte mismatched, it jumped to a block that printed "Wrong! Try again."

This confirmed that the challenge involved an RC4-encrypted flag, and we needed to reverse the encryption by finding the key and the pre-stored ciphertext.

## 5. Extracting RC4 Parameters

### a. Key Identification

-   During KSA analysis, an instruction `lea rdx,[rip+0xccd]` was found, which resolved to address `0x2020`. This address was within the `.rodata` section, indicating it was a constant string.
-   A modulo operation `(i % 15)` was used to index into this data, suggesting a key length of 15.
-   Dumping 15 bytes from `0x2020` in the `challenge` binary:
    ```bash
    dd if=challenge bs=1 skip=$((0x2020)) count=15 2>/dev/null | hexdump -C
    ```
    Output:
    ```
    00000000  21 61 31 20 61 26 0d 39  61 2b 0d 20 31 66 73     |!a1 a&.9a+. 1fs|
    ```
    The key bytes were `21 61 31 20 61 26 0d 39 61 2b 0d 20 31 66 73`. Note that `0d` is Carriage Return (`\r`), not a period (`.`). The string representation is `!a1 a&\r9a+\r 1fs`.

### b. Key Modification

-   A critical instruction `xor eax, 0x52` was discovered immediately after fetching a key byte `key[i % key_len]` and before it was added to `j` in the KSA. This meant each key byte was XORed with `0x52` during the KSA process.

### c. Ciphertext Identification

-   The comparison loop read from a location at `0x2040`. This address was also within `.rodata`, indicating it was the static ciphertext of the flag.
-   Dumping bytes from `0x2040` (initially 64 bytes, then extended to 66 when the flag revealed its full length):
    ```bash
    dd if=challenge bs=1 skip=$((0x2040)) count=66 2>/dev/null | hexdump -C
    ```
    Output:
    ```
    00000000  8f 36 cf 7d 04 8e 35 ac  0f e8 3f 53 8b 87 ac 26  |.6.}..5...?S...&|
    00000010  18 5b 13 c7 ff a6 1d 92  29 b7 62 af a9 b0 cf 74  |.[......).b....t|
    00000020  d2 99 4e 55 47 a9 77 3b  67 28 cb 52 74 90 47 24  |..NUG.w;g(.Rt.G$|
    00000030  15 94 e1 4e 4d f2 57 ad  7f 5d 22 17 05 08 8b 2a  |...NM.W.."....*|
    00000040  ed f1                                            |..              |
    ```
    The ciphertext bytes are `8f 36 cf 7d 04 8e 35 ac 0f e8 3f 53 8b 87 ac 26 18 5b 13 c7 ff a6 1d 92 29 b7 62 af a9 b0 cf 74 d2 99 4e 55 47 a9 77 3b 67 28 cb 52 74 90 47 24 15 94 e1 4e 4d f2 57 ad 7f 5d 22 17 05 08 8b 2a ed f1`.

## 6. Decryption

A Python script `solve.py` was written to implement the RC4 algorithm with the identified key and ciphertext, including the key modification step.

```python
def rc4_ksa(key_bytes):
    S = list(range(256))
    j = 0
    key_len = len(key_bytes)
    for i in range(256):
        # Apply the modification found in analysis: XOR key byte with 0x52
        modified_key_byte = key_bytes[i % key_len] ^ 0x52
        j = (j + S[i] + modified_key_byte) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, data_len):
    i = 0
    j = 0
    keystream = []
    # Create a copy of S for PRGA so KSA S-box is not modified
    S_prga = list(S) 
    for _ in range(data_len):
        i = (i + 1) % 256
        j = (j + S_prga[i]) % 256
        S_prga[i], S_prga[j] = S_prga[j], S_prga[i]
        K = S_prga[(S_prga[i] + S_prga[j]) % 256]
        keystream.append(K)
    return keystream

# Key bytes derived from hexdump, including 0x0d for Carriage Return
key_hex_str = "21 61 31 20 61 26 0d 39 61 2b 0d 20 31 66 73"
key_bytes = [int(b, 16) for b in key_hex_str.split()]

# Ciphertext bytes from 0x2040
ciphertext_hex = "8f 36 cf 7d 04 8e 35 ac 0f e8 3f 53 8b 87 ac 26 18 5b 13 c7 ff a6 1d 92 29 b7 62 af a9 b0 cf 74 d2 99 4e 55 47 a9 77 3b 67 28 cb 52 74 90 47 24 15 94 e1 4e 4d f2 57 ad 7f 5d 22 17 05 08 8b 2a ed f1"
ciphertext = bytes.fromhex(ciphertext_hex.replace(" ", ""))

S_ksa = rc4_ksa(key_bytes)
keystream = rc4_prga(S_ksa, len(ciphertext))

decrypted_bytes = []
for c, k in zip(ciphertext, keystream):
    decrypted_bytes.append(c ^ k)

print("Decrypted bytes:", decrypted_bytes)
print("Decrypted string:", bytes(decrypted_bytes))
```

Running `python3 solve.py` produced:

```
Decrypted string: b'flag{$t0p_JUmp1n9_@R0uNd_1!k3_A_F00l_4nd_gib3_M3333_7H@t_f14g!!!!}'
```

## 7. Verification

To verify the decrypted flag, the executable needed to be run with execute permissions. After restoring execute permissions:

```bash
chmod +x challenge
echo 'flag{$t0p_JUmp1n9_@R0uNd_1!k3_A_F00l_4nd_gib3_M3333_7H@t_f14g!!!!}' | ./challenge
```

Output:
```
Enter the flag: Correct! You got the flag!
```

This confirmed the flag was correctly identified.

## Flag

`flag{$t0p_JUmp1n9_@R0uNd_1!k3_A_F00l_4nd_gib3_M3333_7H@t_f14g!!!!}`

```
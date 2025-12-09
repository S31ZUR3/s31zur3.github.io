rev
## Challenge Overview

We are given a binary (`flag_verifier`) that asks for a flag input. Static analysis reveals that the validation logic is not present in the `.text` section. Instead, the program allocates executable memory, copies a blob of data into it, and executes that data as a function.

## Step 1: Static Analysis

Opening the binary in a decompiler (Ghidra/Binary Ninja/IDA) reveals the following control flow in `main`:

1. User input is read via `getline`.
    
2. `mmap` is called to allocate a memory region with permissions `7` (**RWX** - Read, Write, Execute).
    
3. `memcpy` moves a chunk of bytes from a global data section (`0x404020`) into this new memory.
    
4. The program casts the allocated memory address to a function pointer and calls it: `rax_2(input_string, input_length)`.
    

This confirms the binary is a **Shellcode Runner**. To solve it, we must analyze the code generated at runtime.

## Step 2: Dynamic Analysis (Bypassing PIE)

Running `checksec` reveals that **PIE (Position Independent Executable)** is enabled, meaning memory addresses are randomized at every run. We cannot simply break at the static offset.

**Strategy:**

1. Run the program in GDB and let it load.
    
2. Interrupt execution while it waits for input.
    
3. Find the base address and calculate the offset to the shellcode invocation.
    

**GDB Steps:**

Bash

```
gdb ./flag_verifier
(gdb) start
(gdb) continue
# Program waits for input... Press Ctrl+C
^C
(gdb) info proc mappings
```

_We identified the Base Address (e.g., `0x555555554000`)._

We located the `call` instruction at offset `0x134c`. **Breakpoint Address:** `Base Address + 0x134c`.

## Step 3: Analyzing the Shellcode

After setting the breakpoint and providing dummy input (`AAAA`), we stepped (`si`) into the mapped memory.

Disassembling the shellcode (`x/20i $pc`) revealed the following logic:

### 1. Length Check

Code snippet

```
cmpl   $0x1d,-0x4c(%rbp)  ; 0x1d = 29 decimal
je     ...
```

The flag must be exactly **29 characters** long.

### 2. Data Loading

The code loads several 64-bit integers onto the stack using `movabs`. These represent the encrypted flag bytes in **Little Endian**.

- `0x9ff8e6a5c0d784d5`
    
- `0xecc29cfad3aeedcf`
    
- ...and others.
    

### 3. Key Loading

The code initializes a rolling XOR key:

Code snippet

```
movw   $0xf183,-0x33(%rbp)  ; Stores bytes 0x83, 0xF1
movb   $0xa0,-0x31(%rbp)    ; Stores byte  0xA0
```

Key: `[0x83, 0xF1, 0xA0]`

### 4. Decryption Loop

The loop logic was identified as:

1. Load encrypted byte.
    
2. Load key byte (cycling through the 3-byte key).
    
3. XOR them (`encrypted ^ key`).
    
4. Compare result with user input.
    

## Step 4: Solving

We extracted the encrypted bytes and the key from the assembly and wrote a Python script to replicate the XOR decryption.

**Solution Script:**

Python

```
#!/usr/bin/env python3

# Key extracted from assembly (Little Endian: 0xf183 -> 83 f1)
# Key sequence: 83 F1 A0
key = [0x83, 0xF1, 0xA0]

# Encrypted chunks extracted from 'movabs' instructions
# We convert them to bytes (Little Endian)
chunks = [
    0x9ff8e6a5c0d784d5,
    0xecc29cfad3aeedcf,
    0xc6aee0c99decc29c, # Note: This chunk overlapped in memory, 
    0x8cedcf98f7c39ff6  # but we reconstruct the stream based on offsets
]

# Reconstructing the raw byte stream
data = bytearray()
data.extend(chunks[0].to_bytes(8, 'little'))
data.extend(chunks[1].to_bytes(8, 'little')[:5]) # Take first 5 bytes to reach next offset
data.extend(chunks[2].to_bytes(8, 'little'))
data.extend(chunks[3].to_bytes(8, 'little'))

# Decrypt
flag = ""
for i in range(29): # We know length is 29
    decrypted_char = data[i] ^ key[i % 3]
    flag += chr(decrypted_char)

print(f"Flag: {flag}")
```

## Flag

`VuwCTF{non_symbolic_function}`
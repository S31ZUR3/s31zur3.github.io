#Pwn 
## Step 1: Initial Analysis & Authentication
We started by analyzing the `securevault` binary. Using the `strings` command, we searched for interesting text strings embedded in the executable.

```bash
strings securevault | grep "password" -C 5
```

We discovered a suspicious string: `Sup3rS3cr3tM@st3r!`.
Running the binary and providing this string when prompted for the "master password" successfully authenticated us, granting access to the main menu.

## Step 2: Vulnerability Discovery
The main menu offered several options. We investigated Option 4, "Leave feedback".
We tested for a buffer overflow by sending a large string of inputs.

```bash
python3 -c 'print("Sup3rS3cr3tM@st3r!\n4\n5\n" + "A"*100 + "\n5\n")' | ./securevault
```

This caused the program to crash (`Segmentation fault`), confirming a stack-based buffer overflow vulnerability in the feedback input buffer.

## Step 3: Exploitation Strategy
To exploit this, we needed to control the instruction pointer (`RIP`).

1.  **Finding the Offset:**
    We generated a cyclic pattern and fed it into the program using `gdb`. The crash occurred at offset **72**. This means 72 bytes of padding are required to fill the buffer and reach the saved return address on the stack.

2.  **Finding the Target (Win Function):**
    We analyzed the binary using `objdump` and `gdb`. We located a section of code that prints the flag. This code was protected by checks against global variables, which normally prevent it from running.

    *   **Target Address:** `0x401d3b`
    *   **Reasoning:** Jumping to this address bypasses the variable checks and directly executes the instructions that print the "Congratulations" message and the flag.

3.  **Security Protections:**
    Analysis revealed:
    *   **No PIE (Position Independent Executable):** The binary is loaded at a fixed address (`0x400000`), so we can hardcode the target address.
    *   **NX (No-Execute) Enabled:** We cannot execute shellcode on the stack, but we can hijack the control flow (ROP).

## Step 4: The Exploit
We constructed a Python script using `pwntools`.

**Payload Structure:**
1.  **Padding:** 72 bytes of junk data (`'A' * 72`).
2.  **Ret Gadget:** `0x401d2d` (address of a `ret` instruction). This was included to ensure the stack was 16-byte aligned before calling functions inside the target code. The x86_64 ABI requires the stack to be aligned before a `call` instruction; otherwise, functions like `printf` or `puts` may crash.
3.  **Target Address:** `0x401d3b` (the code that prints the flag).

**Final Payload:** `[72 bytes padding] + [ret gadget] + [win address]`

## Step 5: Execution
Running the exploit against the remote server:

```python
# ... (connection setup)
payload = b"A" * 72 + p64(0x401d2d) + p64(0x401d3b)
io.sendline(payload)
io.interactive()
```

The program accepted our payload, overwrote the return address, jumped to the flag-printing code, and revealed the flag.

**Flag:** `esch{flows-can-be-hijacked-lunar-falcon-2038}`
misc
## Tools Used
- `file`: To identify the type of the executable.
- `strings`: To extract printable strings from the binary.
- `objdump`: To disassemble the executable and inspect its sections.

## Analysis Steps

### 1. Initial Reconnaissance
First, I used `file` to determine the executable's type:
```bash
file crackme
# Output: crackme: ELF 64-bit LSB pie executable, x86-64, ... not stripped
```
The output indicated it was a 64-bit ELF executable and, crucially, "not stripped", meaning symbol information was still present, which simplifies reverse engineering.

Next, I ran `strings` to look for any immediately obvious clues, such as hardcoded passwords, error messages, or flag formats.
```bash
strings crackme | head -n 20
```
This revealed several interesting strings:
- "Enter your username:"
- References to OpenSSL functions like `EVP_DigestInit_ex`, `EVP_sha256`, `EVP_DigestUpdate`, `EVP_DigestFinal_ex`. This immediately suggested that a SHA-256 hash calculation was involved.

### 2. Disassembly and Logic Flow
Given the SHA-256 references, the next step was to disassemble the `main` function using `objdump` to understand the program's logic flow.

```bash
objdump -d -M intel --no-show-raw-insn crackme | grep -A 50 "<main>:"
```
The disassembly revealed a two-stage authentication process:

#### Stage 1: Username Check
The program first prompts for a username. It then compares this input using `strcmp` against a hardcoded string. If the username is incorrect, the program exits. The target username was found by inspecting the address referenced by the `strcmp` call (e.g., `lea rax,[rip+0xc24] # 205a <k4+0x3a>`).
By examining the `.rodata` section at `0x205a`, the username was identified as:
```
# From objdump -s -j .rodata crackme
...
 2050 726e616d 65006164 6d696e00   username.admin.
...
```
The username required is `admin`.

#### Stage 2: Password Hash Check
After a successful username entry, the program prompts for a "password". This input is then passed to a function `compute_sha256` (which uses the OpenSSL functions identified earlier). The resulting SHA-256 hash (32 bytes) is then compared using `memcmp` against a hardcoded 32-byte value stored on the stack.

The hardcoded target hash was constructed from four 8-byte (QWORD) values, `k1`, `k2`, `k3`, and `k4`, loaded from the `.rodata` section into a stack buffer at the beginning of the `main` function.

To retrieve the complete 32-byte hash, the `.rodata` section was dumped:
```bash
objdump -s -j .rodata crackme
```
The relevant bytes were found concatenated from `0x2008`:
- `k1` (at `0x2008`): `fcf730b6d95236ec`
- `k2` (at `0x2010`): `d3c9fc2d92d7b6b2`
- `k3` (at `0x2018`): `bb061514961aec04`
- `k4` (at `0x2020`): `1d6c7a7192f592e4`

Concatenating these bytes (in hex format) yielded the target SHA-256 hash:
`fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4`

### 3. Solution
The username is `admin`.
The target SHA-256 hash is `fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4`.

The user provided the plaintext password `secret123` which hashes to this value.

## The Flag
By entering `admin` as the username and `secret123` as the password, the program would accept the input. The flag format is `UNLP{<password>}`.

Therefore, the flag is:
`UNLP{secret123}`
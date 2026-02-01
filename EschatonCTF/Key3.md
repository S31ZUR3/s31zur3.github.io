#Rev 
## 1. Initial Reconnaissance

The target is a stripped 64-bit ELF binary named `validator`. Running it without arguments reveals the expected usage:
```
Usage: ./validator <username> <hwid> <timestamp> <tier> <key>
  username: 4-32 printable ASCII characters
  hwid: 16-character hex string
  timestamp: Unix epoch timestamp
  tier: 1 (Bronze), 2 (Silver), or 3 (Gold)
  key: KGIII-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-YYYY format
```

Strings analysis suggests the binary was written in **Rust**, indicated by common panic messages and library paths (e.g., `/rustc/.../library/core/src/time.rs`).

## 2. Static and Dynamic Analysis

### A. Argument Validation
The binary first performs basic checks:
- **Username length**: Must be between 4 and 32 characters.
- **HWID**: Must be a 16-character hex string (representing 8 bytes).
- **Tier**: Must be 1, 2, or 3.
- **Key Format**: Must start with `KGIII-`, followed by four 8-character hex segments, and end with a tier-specific suffix (`BRNZ`, `SLVR`, or `GOLD`).

### B. The Timestamp Constraint
During dynamic analysis with GDB, I identified a critical check at offset `0x27f7`:
```assembly
lea    0x15180(%rcx), %rax
cmp    %r15, %rax
jb     31c0
```
`0x15180` is 86,400 seconds (exactly 24 hours). The binary compares the provided timestamp against the current system time. **A key is only valid if its timestamp is within ±24 hours of the system clock.**

### C. Cryptographic Primitives
The binary uses two main algorithms:
1.  **CRC-32**: Calculated over the 8 bytes of the HWID.
2.  **SHA-256**: The binary utilizes x86-64 hardware-accelerated instructions (`sha256rnds2`, `sha256msg1`, etc.).
    -   **Input Buffer**: `username + hwid_bytes + timestamp (8 bytes, little-endian) + tier (1 byte)`.
    -   **Result**: The first 16 bytes (4 words) of the SHA-256 digest are used as the starting state for the final transformation.

### D. The Custom Transformation
The core of the validation is a complex sequence of bitwise operations involving the CRC-32 result and the SHA-256 words. I traced these instructions from `0x2f11` to `0x302e`.

The logic involves:
-   **Register Rotation**: Heavy use of `rol` (Rotate Left).
-   **Chained Dependencies**: Registers `eax`, `ecx`, `edx`, `esi`, `edi`, `r8d`, `r9d`, `r10d`, `r13d`, and `r15d` are updated in a block-cipher-like structure.
-   **Magic Constants**: The constant `0x5f8c2e7a` is XORed at multiple stages.

One of the trickiest parts was identifying the word ordering of the SHA-256 digest. While most words were treated as big-endian, the assembly specifically unpacked the third word (`s2`) using a little-endian convention relative to its position in the digest.

## 3. Keygen Implementation

The `keygen.py` was built by meticulously translating the x86-64 assembly into Python.

### Mapping Registers to Key Segments:
After the transformation is complete, the registers map to the key segments as follows:
-   **Segment 1**: `r15d` (after the final XOR/SUB chain).
-   **Segment 2**: `r13d` (final state).
-   **Segment 3**: `eax` (final state).
-   **Segment 4**: `esi` (rotated result of the `edx` chain).

### Success Criteria:
To ensure every generated key is valid:
1.  **Timestamp**: The script requires a fresh timestamp (usually `$(date +%s)`).
2.  **Endianness**: The script strictly follows the binary's internal byte-order logic for the SHA-256 digest.
3.  **Tier Mapping**: The tier integer (1-3) is mapped to its string suffix (`BRNZ`, `SLVR`, `GOLD`).
   ```python
   import hashlib
import binascii
import struct
import sys

def rol(val, n):
    return ((val << n) & 0xFFFFFFFF) | (val >> (32 - n))

def generate_key(username, hwid_hex, timestamp, tier):
    hwid_bytes = bytes.fromhex(hwid_hex)
    timestamp_bytes = struct.pack('<Q', timestamp)
    tier_byte = struct.pack('<B', tier)

    data = username.encode() + hwid_bytes + timestamp_bytes + tier_byte
    sha256_res = hashlib.sha256(data).digest()

    s0 = struct.unpack('<I', sha256_res[0:4])[0]
    s1 = struct.unpack('<I', sha256_res[4:8])[0]
    s2 = struct.unpack('<I', sha256_res[8:12])[0]
    s3 = struct.unpack('<I', sha256_res[12:16])[0]

    crc = binascii.crc32(hwid_bytes)

    eax = crc
    ecx = s0
    r13 = s1
    r15 = s3

    ecx ^= eax # 2f1b
    r13 = (r13 + ecx) & 0xFFFFFFFF # 2f1d
    r8 = ecx # 2f20
    ecx = r13 # 2f23
    ecx = rol(ecx, 25) # 2f26
    r13 = rol(r13, 4) # 2f29
    r13 ^= s2 # 2f2d
    edi = r13 # 2f31
    edi ^= 0x5f8c2e7a # 2f34
    r15 = (r15 - edi) & 0xFFFFFFFF # 2f3a
    r15 ^= r8 # 2f3d
    esi = eax # 2f40
    esi = rol(esi, 3) # 2f42
    edi ^= esi # 2f45
    r15 = (r15 + edi) & 0xFFFFFFFF # 2f47
    edx = r15 # 2f4a
    edx = rol(edx, 25) # 2f4d
    r15 = rol(r15, 4) # 2f50
    r15 ^= r8 # 2f54
    r8 = r15 # 2f57
    r8 ^= 0x5f8c2e7a # 2f5a
    ecx = (ecx - r8) & 0xFFFFFFFF # 2f61
    ecx ^= edi # 2f64
    edi = eax # 2f66
    edi = rol(edi, 6) # 2f68
    r8 ^= edi # 2f6b
    ecx = (ecx + r8) & 0xFFFFFFFF # 2f6e
    r10 = ecx # 2f71
    r10 = rol(r10, 25) # 2f74
    ecx = rol(ecx, 4) # 2f78
    esi ^= r13 # 2f7b
    esi ^= ecx # 2f7e
    edx = (edx - esi) & 0xFFFFFFFF # 2f80
    r9 = eax # 2f82
    r9 = rol(r9, 9) # 2f85
    edx ^= r8 # 2f89
    r9 ^= esi # 2f8c
    edx = (edx + r9) & 0xFFFFFFFF # 2f8f
    ecx = edx # 2f92
    ecx = rol(ecx, 25) # 2f94
    edx = rol(edx, 4) # 2f97
    edi ^= r15 # 2f9a
    edi ^= edx # 2f9d
    r10 = (r10 - edi) & 0xFFFFFFFF # 2f9f
    r10 ^= r9 # 2fa2
    r8 = eax # 2fa5
    r8 = rol(r8, 12) # 2fa8
    r8 ^= edi # 2fac
    r10 = (r10 + r8) & 0xFFFFFFFF # 2faf
    esi = r10 # 2fb2
    esi = rol(esi, 25) # 2fb5
    r10 = rol(r10, 4) # 2fb8
    r10 ^= r9 # 2fbc
    r9 = r10 # 2fbf
    r9 ^= 0x5f8c2e7a # 2fc2
    ecx = (ecx - r9) & 0xFFFFFFFF # 2fc9
    ecx ^= r8 # 2fcc
    edi = eax # 2fcf
    edi = rol(edi, 15) # 2fd1
    r9 ^= edi # 2fd4
    ecx = (ecx + r9) & 0xFFFFFFFF # 2fd7
    edx = ecx # 2fda
    edx = rol(edx, 25) # 2fdc
    ecx = rol(ecx, 4) # 2fdf
    ecx ^= r8 # 2fe2
    r8 = ecx # 2fe5
    r8 ^= 0x5f8c2e7a # 2fe8
    esi = (esi - r8) & 0xFFFFFFFF # 2fef
    esi ^= r9 # 2ff2
    r15_new = eax # 2ff5
    r15_new = rol(r15_new, 18) # 2ff8
    r8 ^= r15_new # 2ffc
    esi = (esi + r8) & 0xFFFFFFFF # 2fff
    r13 = esi # 3002
    r13 = rol(r13, 25) # 3005
    esi = rol(esi, 4) # 3009
    edi ^= r10 # 300c
    edi ^= esi # 300f
    edx = (edx - edi) & 0xFFFFFFFF # 3011
    eax_final = eax # 3013
    eax_final = rol(eax_final, 21) # 3013
    edx ^= r8 # 3016
    eax_final ^= edi # 3019
    edx = (edx + eax_final) & 0xFFFFFFFF # 301b
    esi_last = edx # 301d
    esi_last = rol(esi_last, 25) # 301f
    edx = rol(edx, 4) # 3022
    r15_last = (r15_new ^ ecx) & 0xFFFFFFFF # 3025
    r15_last = (r15_last ^ edx) & 0xFFFFFFFF # 3028
    r13 = (r13 - r15_last) & 0xFFFFFFFF # 302b
    r13 = (r13 ^ eax_final) & 0xFFFFFFFF # 302e

    part1 = r15_last
    part2 = r13
    part3 = eax_final
    part4 = esi_last

    return f"KGIII-{part1:08x}-{part2:08x}-{part3:08x}-{part4:08x}-{{}}"

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python3 keygen.py <username> <hwid> <timestamp> <tier>")
        sys.exit(1)
    username = sys.argv[1]
    hwid = sys.argv[2]
    timestamp = int(sys.argv[3])
    tier = int(sys.argv[4])
    tier_names = ["", "BRNZ", "SLVR", "GOLD"]
    tier_name = tier_names[tier]
    print(generate_key(username, hwid, timestamp, tier).format(tier_name))
   ```
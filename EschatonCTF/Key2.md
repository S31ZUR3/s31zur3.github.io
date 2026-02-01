#Rev 
## 1. Initial Reconnaissance

The binary `validator` is a 64-bit statically linked and stripped ELF executable. Running it without arguments reveals the expected input format:

```bash
Usage: ./validator <username> <hwid> <key>
  username: 4-20 alphanumeric characters
  hwid: 8-character hex string
  key: A1B2-XXXX-XXXX-XXXX-CCCC format
```

## 2. Reverse Engineering

### Main Function Analysis
The entry point (`0x4056e0`) leads to the main logic at `0x404db0`. The program performs the following checks:
1. **Argument Count**: Ensures 3 arguments are provided.
2. **Username Validation**: Checks if the length is between 4 and 20 and contains only alphanumeric characters or underscores.
3. **HWID Validation**: Validates the HWID as an 8-character hex string and converts it to a 32-bit integer.
4. **Key Format**: Ensures the key is 24 characters long and follows the `A1B2-XXXX-XXXX-XXXX-CCCC` pattern, verifying the placement of hyphens.

### The Algorithm
The core validation involves several cryptographic-like steps:

#### A. Custom Hash Function (`0x405900`)
The program uses a custom hashing/checksum function for both the username and a final verification step.
- **Initial State**: `h = 0x4e7f2a19`
- **Transformation**: For each byte `c` at index `i`:
    1. `rsi = (c << ((i & 3) << 3)) ^ h`
    2. `rsi = rotate_left(rsi, 5)`
    3. `edx = rsi + 0x3c91e6b7`
    4. `eax = rotate_right(edx, 11)`
    5. `h = eax ^ edx`

#### B. Key Segment Generation
1. **Seed**: `seed = checksum(username) ^ hwid`
2. **Segment 2**: Computed using `(rotate_left(seed, 7) ^ 0x8d2f5a1c)`. The lower 16 bits must match the second segment of the key.
3. **Segment 3**: Takes the result from the previous step, swaps/XORs the high and low 16-bit words with constants `0x6b3e` and `0x1fa9`. The lower 16 bits must match the third segment.
4. **Segment 4**: Computed using `(rotate_right(result_from_step_3, 13) + 0x47c83d2e)`. The lower 16 bits must match the fourth segment.

#### C. Final Verification (Segment 5)
The program packs the 16-bit values of segments 2, 3, and 4 into a 6-byte buffer (little-endian). It runs the custom hash function on this buffer, then XORs the lower 16 bits of the result with `0x52b1`. This must match the fifth segment of the key.

## 3. Keygen Implementation

The following Python script implements the discovered logic:

```python
def rol(val, n, bits=32):
    return ((val << n) & (2**bits - 1)) | (val >> (bits - n))

def ror(val, n, bits=32):
    return (val >> n) | ((val << (bits - n)) & (2**bits - 1))

def checksum(data):
    h = 0x4e7f2a19
    for i, c in enumerate(data):
        shift = (i & 3) << 3
        rsi = (c << shift) ^ h
        rsi = rol(rsi, 5)
        edx = (rsi + 0x3c91e6b7) & 0xFFFFFFFF
        eax = ror(edx, 11)
        h = eax ^ edx
    return h

def generate_key(username, hwid_hex):
    hwid = int(hwid_hex, 16)
    u_hash = checksum(username.encode())
    seed = hwid ^ u_hash

    # Segment 2
    res0 = (rol(seed, 7) ^ 0x8d2f5a1c) & 0xFFFFFFFF
    p2 = res0 & 0xFFFF

    # Segment 3
    v_low, v_high = res0 & 0xFFFF, (res0 >> 16) & 0xFFFF
    res1 = ((v_low ^ 0x6b3e) << 16) | (v_high ^ 0x1fa9)
    p3 = res1 & 0xFFFF

    # Segment 4
    res2 = (ror(res1, 13) + 0x47c83d2e) & 0xFFFFFFFF
    p4 = res2 & 0xFFFF

    # Segment 5
    buf = bytearray([p2 & 0xFF, p2 >> 8, p3 & 0xFF, p3 >> 8, p4 & 0xFF, p4 >> 8])
    p5 = (checksum(buf) & 0xFFFF) ^ 0x52b1

    return f"A1B2-{p2:04X}-{p3:04X}-{p4:04X}-{p5:04X}"
```

## 4. Verification

Testing with `username: testuser` and `hwid: 12345678`:
- Generated Key: `A1B2-AAB9-05F1-4966-1ABE`
- Output: `Valid!`
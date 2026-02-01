#Rev 
## 1. Initial Reconnaissance

We began by inspecting the provided binary `validator` to understand its basic properties and expected usage.

```bash
$ file validator
validator: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, ...
```

Running the binary revealed the required input format:

```bash
$ ./validator
Usage: ./validator <username> <key>
  username: 4-16 alphanumeric characters
  key: XXXX-XXXX-XXXX-XXXX format
```

## 2. Static Analysis

We used `objdump` and `nm` to identify the entry point and main logic.

- **Main Function**: Located at `0x401930`.
- **Validation Logic**: The `main` function parses arguments and calls a subroutine at `0x401b00` (which we'll call `proc_a`) to validate the key against the username.

### 2.1 Analyzing the Validation Function (`proc_a`)

Disassembling the function at `0x401b00` revealed two distinct phases:
1.  **Username Hashing**: A loop iterating over the username characters.
2.  **Key Generation & Checking**: A sequence of bitwise operations deriving values to compare against the input key parts.

#### The Hashing Algorithm

The hashing loop (addresses `0x401c40` - `0x401c52`) implements a variant of the DJB2 hash algorithm.

```assembly
401c46: shl    $0x5,%ecx       ; ecx = hash << 5
401c49: add    %ecx,%eax       ; eax = hash + (hash << 5) -> hash * 33
401c4b: add    %edx,%eax       ; eax = eax + char_value
```

**Python Equivalent:**
```python
h = 0x7a2f  # Initial seed (31279)
for c in username:
    val = ord(c)
    h = (h * 33 + val) & 0xFFFFFFFF
```

## 3. Deriving the Key Generation Logic

After the hash `H` is computed, the binary performs a series of register manipulations to generate the four 16-bit parts of the key (K1, K2, K3, K4). We traced the state of the registers `eax`, `esi`, `edx`, and `ecx` instruction by instruction.

### Register State Tracking

Let `H` be the final hash of the username.

1.  **Initialization**:
    - `eax` = `H`
    - `esi` = `H`

2.  **Transformation Sequence**:
    - **EDX setup**: `edx = (H * 8)` (via `lea 0x0(,%rax,8),%edx`)
    - **EAX modification**:
        - `ax = (H >> 5)` (arithmetic right shift of lower 16 bits)
        - `eax = eax ^ edx`
    - **ESI modification (Basis for K1)**:
        - `si = si ^ 0x9c3e`
    - **EAX finalization (Basis for K2)**:
        - `ax = ax ^ 0xb7a1`
    - **EDX calculation (Basis for K3)**:
        - `edx = esi + eax`
        - `dx = dx ^ 0xe4d2`
    - **ECX calculation (Basis for K4)**:
        - `ecx = eax ^ (esi + eax)` (Note: `ecx` gets `eax` before `edx` was modified)
        - `cx = cx ^ 0x78ec`

### Key Extraction

The code compares the user's input key parts (parsed from hex) against the lower 16 bits of these registers:

- **K1**: `si` (lower 16 bits of `esi`)
- **K2**: `ax` (lower 16 bits of `eax`)
- **K3**: `dx` (lower 16 bits of `edx`)
- **K4**: `cx` (lower 16 bits of `ecx`)

## 4. The Keygen Script

We implemented the reversed logic in a Python script (`solve.py`).

```python
def calc_key(username):
    # 1. Compute Hash
    h = 0x7a2f
    for c in username:
        val = ord(c)
        h = (h * 33 + val) & 0xFFFFFFFF

    # 2. Derive Key Parts
    # Mimic register states
    esi = h
    eax = h

    # edx calculation (line 401c54)
    edx = (h * 8) & 0xFFFFFFFF

    # eax shift and xor (lines 401c5d - 401c61)
    # Note: The shr $0x5,%ax only affects the lower 16 bits in the register view,
    # but for calculation purposes we simulate the logic:
    eax_after_shr = (h & 0xFFFF0000) | ((h & 0xFFFF) >> 5)
    eax = eax_after_shr ^ edx

    # K1 calculation (lines 401c63)
    esi = (esi & 0xFFFF0000) | ((esi & 0xFFFF) ^ 0x9c3e)
    k1 = esi & 0xFFFF

    # K2 calculation (lines 401c68)
    eax = (eax & 0xFFFF0000) | ((eax & 0xFFFF) ^ 0xb7a1)
    k2 = eax & 0xFFFF

    # K3 calculation (lines 401c6c - 401c73)
    # The LEA adds the current ESI and EAX
    val_for_edx = (esi + eax) & 0xFFFFFFFF
    k3 = (val_for_edx ^ 0xe4d2) & 0xFFFF

    # K4 calculation (lines 401c6f - 401c78)
    # logic: mov %eax,%ecx -> xor %edx,%ecx
    # Here %edx held the (esi+eax) value before the final XOR.
    val_for_ecx = eax ^ val_for_edx
    k4 = (val_for_ecx ^ 0x78ec) & 0xFFFF

    return f"{k1:04x}-{k2:04x}-{k3:04x}-{k4:04x}"
```

## 5. Verification

We verified the keygen with the `validator` binary:

```bash
$ python3 solve.py gemini
2b96-0f5c-de20-4d42

$ ./validator gemini 2b96-0f5c-de20-4d42
Valid!
```

This confirms the reverse engineering was successful.
crypto
## Analysis
The encryption script performs the following steps:

1. **Seed Generation:**
   A seed `s` is calculated based on the flag's content:
   ```python
   s = ((sum(F) << 3) ^ (len(F) * 1337)) & 0xffffffff
   ```
   This means the seed depends entirely on the **sum of the characters** and the **length** of the flag.

2. **Stream Generation:**
   A function `p(s)` generates a 128-byte pseudo-random stream `st` using a linear congruential generator (LCG) derived logic.

3. **Key & IV Derivation:**
   An AES key `k` and IV `v` are derived from the stream `st` using SHA-256 and MD5 hashes.

4. **Flag Transformation:**
   The flag `F` undergoes a custom transformation:
   - XOR with bytes from `st`.
   - Bitwise rotation.
   - The entire byte array is reversed.

5. **Encryption:**
   The transformed flag is padded and encrypted using AES-CBC with the derived key and IV.

## Vulnerability
The critical weakness lies in the seed generation. The seed `s` is derived solely from `sum(F)` and `len(F)`.
- The length of a typical CTF flag is usually between 10 and 100 characters.
- The sum of the characters is bounded by the ASCII values of printable characters (approx 32 to 126 per character).

This search space is small enough to brute-force. We can iterate over possible lengths (`L`) and sums (`S`) to generate candidate seeds.

## Solution Strategy
1. Iterate through possible flag lengths `L` (e.g., 10 to 100).
2. Iterate through possible sums `S` (range `L * 32` to `L * 126`).
3. For each pair `(L, S)`:
   - Calculate the candidate seed `s`.
   - Generate the stream `st`.
   - Derive the candidate AES Key `k` and IV `v`.
   - Attempt to decrypt the ciphertext from `output.txt`.
   - If decryption (and unpadding) succeeds, reverse the bitwise transformations.
   - Check if the resulting plaintext starts with the flag format `ShaZ{`.

## Solver Script
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

# Ciphertext from output.txt
ciphertext_hex = "bb4bcb9794fdca19bf6b8c831b7a8829bf530883c5f8a3ab5e70bae800f5a383b43d1c93b5328260e5ad185439c991c0"
ciphertext = bytes.fromhex(ciphertext_hex)

def p(s):
    x = s
    o = []
    for i in range(128):
        x = (x * 1103515245 + 12345 + i) & 0xffffffff
        o.append((x ^ (x >> 16)) & 0xff)
    return bytes(o)

def attempt_decrypt(L, S):
    s = ((S << 3) ^ (L * 1337)) & 0xffffffff

    st = p(s)

    # Key derivation
    a = hashlib.sha256(st[:64]).digest()
    b = hashlib.sha256(st[64:] + a[:11]).digest()

    k = hashlib.sha256(b + a).digest()[:16]
    v = hashlib.md5(a).digest()

    try:
        cipher = AES.new(k, AES.MODE_CBC, v)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, 16)
    except ValueError:
        return None

    if len(decrypted) != L:
        return None

    # Reverse transformation
    x = bytearray(decrypted[::-1])

    for i in range(len(x)):
        n = i % 6 + 1
        val = x[i]
        # Inverse Rotate
        x[i] = ((val >> n) | (val << (8 - n))) & 0xff
        # Inverse XOR
        x[i] ^= st[(i * 9) % len(st)]

    return x

print("Starting brute-force...")
for L in range(10, 100):
    min_S = L * 32
    max_S = L * 126

    for S in range(min_S, max_S + 1):
        res = attempt_decrypt(L, S)
        if res:
            try:
                flag = res.decode()
                if flag.startswith("ShaZ{"):
                    print(f"Found flag! Length: {L}, Sum: {S}")
                    print(flag)
                    exit(0)
            except UnicodeDecodeError:
                continue
```

## Result
Running the solver yields:
**Flag:** `ShaZ{1_7h0ugh7_it_w1ll_b3_4_h4rd_0n3_nvm!!!}`
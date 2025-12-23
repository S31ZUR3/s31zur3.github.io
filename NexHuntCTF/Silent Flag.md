Cryptography
### 1. File Analysis

We are given four files representing a raw Ethereum event log export:

- `abi.json`: Defines the event structure.
    
- `topic0`: The Keccak-256 hash of the event signature.
    
- `topic1`: The first indexed parameter.
    
- `data`: The non-indexed parameters (ABI encoded).
    

**The ABI Definition:** The `abi.json` file reveals the specific event we are looking at:

JSON

```
Event: Stored(bytes32 indexed id, bytes data)
```

- `id` is **indexed**, meaning it is stored in `topic1`.
    
- `data` is **not indexed**, meaning it is stored in the `data` file.
    

### 2. Decoding the Log Data

**Analyzing `topic1` (The ID):** The file content is `0x00...001337`.

- Value: `0x1337`
    

**Analyzing `data` (The Payload):** The `data` file contains a continuous hex string. Since it is ABI encoded, we must parse it in 32-byte chunks:

1. **Offset (Bytes 0-31):** `0000...000020` -> `0x20` (32 decimal). This indicates the dynamic bytes start immediately after the length field.
    
2. **Length (Bytes 32-63):** `0000...00001c` -> `0x1c` (28 decimal). The flag is 28 characters long.
    
3. **Content (Bytes 64-95):** `59524f42444c6f07656803757e68730474077306797068050705024a` (+ padding)
    

**Extracted Ciphertext:** `59524f42444c6f07656803757e68730474077306797068050705024a`

### 3. Decryption Logic

The extracted text is not readable ASCII. Given the context (CTF), we suspect a simple XOR cipher. We can derive the key using a "Known Plaintext Attack" assuming the flag format starts with `nexus`.

- **Ciphertext Byte 1:** `0x59`
    
- **Expected Plaintext Byte 1:** `'n'` (`0x6E`)
    

Key=0x59⊕0x6E=0x37

**Verification:** The value in `topic1` was `0x...1337`. The last byte is `0x37`. This confirms `0x37` is the intended key.

### 4. Solution Script

We can write a quick Python script to decode the byte string.

Python

```
# Extracted payload from the data file
cipher_hex = "59524f42444c6f07656803757e68730474077306797068050705024a"
ciphertext = bytes.fromhex(cipher_hex)

# Key derived from topic1 (last byte of 0x1337)
key = 0x37

# XOR Decryption
flag = "".join([chr(byte ^ key) for byte in ciphertext])

print(f"Flag: {flag}")
```

### 5. Final Flag

Running the script yields:

**`nexus{X0R_4BI_D3C0D1NG_2025}`**


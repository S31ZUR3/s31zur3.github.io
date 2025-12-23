1. Initial Analysis

We started with a 64-bit ELF binary named challenge. Running strings on the binary revealed a critical clue:
Plaintext

expand 32-byte k

This string is the distinct sigma constant used in ChaCha20 and Salsa20 stream ciphers. This immediately suggests that the flag is being encrypted or decrypted using one of these algorithms.
2. Static Analysis (Decompilation)

Opening the binary in a decompiler (like Ghidra) revealed a main function calling a subroutine FUN_00101592. Analyzing this subroutine confirmed the encryption logic.
The Encryption Routine

The function initializes a state matrix using the constants found earlier:

    0x61707865 ("apxe")

    0x3320646e ("3 dn")

    0x79622d32 ("yb-2")

    0x6b206574 ("k et")

Reversed (Little Endian), this spells "expand 32-byte k". The code then performs an XOR operation on the input buffer, confirming it is a stream cipher.
Identifying the Secrets

To decrypt the flag, we needed three components: the Key, the Nonce (IV), and the Ciphertext. By analyzing the memory addresses in the decompiled code, we mapped the virtual addresses to file offsets:

    The Key (32 bytes):

        Location: 0x2080

        Value: A sequential pattern 00 01 02 ... 1F.

    The Nonce (12 bytes):

        Location: 0x20A0

        Value: Mostly nulls with 4A in the middle (000000000000004a00000000).

    The Ciphertext:

        Location: 0x2040

        Analysis: The main function passed a pointer to this address as the first argument to the encryption function. It contained roughly 34 bytes of raw binary data.

3. The Problem

Attempting to debug with GDB was inconsistent. Additionally, standard Python libraries (PyCryptodome) sometimes handle the ChaCha20 block counter differently (starting at 0 vs 1). The binary explicitly initialized the block counter to 1.
4. The Solution

We wrote a Python script to manually implement the ChaCha20 block function. This allowed us to:

    Extract the Key, Nonce, and Ciphertext directly from the binary file using the offsets found in Step 2.

    Force the block counter to start at 1 to match the binary's behavior.

    XOR the generated keystream with the ciphertext.

Solver Script
```python 
import struct

def rotl32(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def chacha20_block(key, counter, nonce):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = list(struct.unpack('<8I', key))
    n = list(struct.unpack('<3I', nonce))
    state = constants + k + [counter] + n
    working_state = list(state)
    
    # 20 rounds (Standard ChaCha20)
    for _ in range(10): 
        def qr(a, b, c, d):
            a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 16)
            c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 12)
            a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 8)
            c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 7)
            return a, b, c, d
        
        # Column & Diagonal rounds
        working_state[0], working_state[4], working_state[8], working_state[12] = qr(working_state[0], working_state[4], working_state[8], working_state[12])
        working_state[1], working_state[5], working_state[9], working_state[13] = qr(working_state[1], working_state[5], working_state[9], working_state[13])
        working_state[2], working_state[6], working_state[10], working_state[14] = qr(working_state[2], working_state[6], working_state[10], working_state[14])
        working_state[3], working_state[7], working_state[11], working_state[15] = qr(working_state[3], working_state[7], working_state[11], working_state[15])
        working_state[0], working_state[5], working_state[10], working_state[15] = qr(working_state[0], working_state[5], working_state[10], working_state[15])
        working_state[1], working_state[6], working_state[11], working_state[12] = qr(working_state[1], working_state[6], working_state[11], working_state[12])
        working_state[2], working_state[7], working_state[8], working_state[13] = qr(working_state[2], working_state[7], working_state[8], working_state[13])
        working_state[3], working_state[4], working_state[9], working_state[14] = qr(working_state[3], working_state[4], working_state[9], working_state[14])

    return b''.join(struct.pack('<I', (working_state[i] + state[i]) & 0xffffffff) for i in range(16))

with open("challenge", "rb") as f:
    data = f.read()
    key = data[0x2080:0x20a0]
    nonce = data[0x20a0:0x20ac]
    cipher = data[0x2040:0x2062]
    
    keystream = chacha20_block(key, 1, nonce)
    print(bytes(a ^ b for a, b in zip(cipher, keystream)).decode())
```

5. The Flag

Running the script produced the flag:

flag{iN1_f!ni_Min1_m0...1_$e3_yOu}

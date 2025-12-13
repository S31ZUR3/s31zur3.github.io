

---

### 1. Initial Reconnaissance

We started with a Windows executable named `grace.exe`.

- **File Analysis:** The file headers contained strings like `UPX0`, `UPX1`, and `4.22 UPX!`, suggesting the binary was packed.
    
- **Deception:** Running `upx -d grace.exe` failed, indicating the UPX headers were likely spoofed or the file was modified to prevent standard unpacking. However, opening the file in a decompiler (Ghidra) revealed readable code immediately, meaning the executable was not actually packed, or the "packing" was just section naming obfuscation.
    

### 2. Static Analysis (The Code)

Analyzing the `entry` function in Ghidra revealed the program's core logic:

1. **Input:** The program reads 64 bytes of user input (the password).
    
2. **Verification:** It processes this input through a complex hashing loop involving bitwise operations and a lookup table.
    
3. **The Check:** The result of the hash is compared to a hardcoded value `0x668bfb55`.
    
4. **The Vulnerability:**
    
    - If the hash matches, the program jumps to a **decryption loop**.
        
    - If the hash fails, it decrypts a "failure" message.
        
    - Crucially, **the encrypted flag data and the decryption key are hardcoded in the binary.**
        

We did not need to reverse the complex hash or find the correct password because we could simply emulate the decryption process ourselves.

### 3. The Decryption Logic

The decryption routine identified in the code was a simple XOR cipher:

C

```
// Decompiled Logic
for (iVar4 = -0x40; iVar4 != 0; iVar4 = iVar4 + 1) {
    // Encrypted byte XOR Key
    abStack_70[iVar4] = (&UNK_0040515d)[iVar4] ^ 0xbc;
}
```

- **Algorithm:** XOR
    
- **Key:** `0xBC`
    
- **Location:** The loop uses a negative index (`-0x40` to `0`) relative to address `0x0040515d`. This means the data starts at `0x0040511d` (64 bytes prior).
    

### 4. Extraction & Solution

We located the encrypted bytes at offset `0x0040511d` in the binary. The first byte found was `0xD2`.

**Manual Verification:**

- Encrypted Byte: `0xD2`
    
- Key: `0xBC`
    
- Decrypted: `0xD2 ^ 0xBC = 0x6E` -> **'n'**
    

Since the flag format is `nexus{...}`, this confirmed we found the correct data.

**Solver Script:** We used a Python script to extract the 64 bytes from the binary and decrypt them:

Python

```
data = b'\xd2\xd9\xc4\xc7\xc9\xe7\xce\x8f\x89\xcf\xce\xe9\x8d\xca\x8a\xce\x81\x8f\x8d\xcf\x8f\xce\x8e\x89\x8d\xca\x81\xce\x88\x84\xce\x8e\x8e\x83\x8f\x85\xce\x80\x8d\x85\x89\xce\x82\x89\xcf\xce\x8a\x89\xcf\xe9\x89\x88'
key = 0xbc
flag = ''.join([chr(b ^ key) for b in data])
print(flag)
```

### 5. Conclusion

The challenge text ("recursive vm inception") implies the "hash" function we skipped was likely a virtual machine interpreter intended to make reversing the password difficult. However, by identifying that the flag was stored as data and decrypted upon success, we bypassed the VM analysis entirely (a "Known Plaintext" or "Static Extraction" attack).

**Final Flag:** `nexus{r3cur51v3_vm_1nc3p710n_7hr33_l4y3r5_d33p_n357ed}`
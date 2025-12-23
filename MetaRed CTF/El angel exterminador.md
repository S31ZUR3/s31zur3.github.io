crypto

**Challenge Description:**
The challenge presented a file named `flag.png.xor`, suggesting an XOR encryption. The objective was to decrypt this file to obtain the flag.

**Solution Steps:**

1.  **Initial Analysis:**
    The presence of the `.xor` extension indicated a likely XOR encryption. The original file was presumed to be `flag.png`.

2.  **Identifying PNG Signature:**
    PNG files have a standard 8-byte signature: `89 50 4E 47 0D 0A 1A 0A`. This knowledge is crucial for a known-plaintext attack.

3.  **Inspecting the Encrypted File:**
    The first 32 bytes of `flag.png.xor` were extracted using `xxd`:
    `dc 1e 02 17 3f 3a 28 3f 21 55 4e 41 19 7a 74 60 35 21 54 62 4c 50 33 f2 3a 37 21 55 4e 96 01 51`

4.  **XOR Key Derivation (Known-Plaintext Attack):**
    By XORing the first 8 bytes of `flag.png.xor` with the PNG signature, the initial part of the XOR key was revealed:
    `dc ^ 89 = 55 ('U')`
    `1e ^ 50 = 4e ('N')`
    `02 ^ 4e = 4c ('L')`
    `17 ^ 47 = 50 ('P')`
    `3f ^ 0d = 32 ('2')`
    `3a ^ 0a = 30 ('0')`
    `28 ^ 1a = 32 ('2')`
    `3f ^ 0a = 35 ('5')`
    This resulted in `UNLP2025`.

    Further analysis of the subsequent bytes, specifically the expected `IHDR` chunk type (`49 48 44 52`) after the PNG signature, helped confirm and extend the key. The pattern `UNLP2025` followed by `!` and then a repeat of `UNLP202` strongly suggested the key was `UNLP2025!`.

5.  **Decryption Script:**
    A Python script (`decrypt.py`) was created to perform the XOR decryption:

    ```python
    def xor_decrypt(input_path, output_path, key):
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            data = f_in.read()
            key_len = len(key)
            decrypted_data = bytearray()

            for i in range(len(data)):
                decrypted_data.append(data[i] ^ key[i % key_len])

            f_out.write(decrypted_data)

    if __name__ == "__main__":
        key = b"UNLP2025!" # Derived key
        xor_decrypt("flag.png.xor", "flag.png", key)
        print("Decryption complete. Saved to flag.png")
    ```

6.  **Executing the Decryption:**
    The script was executed, successfully creating `flag.png`.

7.  **Verification:**
    The `file` command confirmed that `flag.png` was a valid PNG image:
    `flag.png: PNG image data, 300 x 450, 8-bit/color RGB, non-interlaced`

8.  **Flag Retrieval:**
    The decrypted `flag.png` image, when opened, revealed the flag visually.

**The Flag:**
`UNLP{f4th3r0fsurrealism!}`

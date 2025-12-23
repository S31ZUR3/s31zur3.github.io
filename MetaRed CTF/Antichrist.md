Crypto

This challenge consisted of three levels of cryptographic puzzles, building upon each other.

---
Level 1: Repeating XOR Key
---

Initial analysis of the provided `certunlp_2025_crypto_antichrist.txt` file revealed several plaintext-ciphertext pairs, with ciphertexts represented in hexadecimal.

Example pairs:
- "How are you?": `040e0553371d0b740b06104d`
- "How old are you?": `040e055339030a74131b0052350e074c`
- etc.

The lengths of the plaintexts matched the byte lengths of their respective hex ciphertexts, strongly suggesting a repeating XOR cipher. To find the key, I performed an XOR operation between each plaintext and its corresponding ciphertext (`Key = Plaintext XOR Ciphertext`).

Python script `analyze_keys.py`:
```python
def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

examples = [
    (b"How are you?", bytes.fromhex("040e0553371d0b740b06104d")),
    (b"How old are you?", bytes.fromhex("040e055339030a74131b0052350e074c")),
    (b"Plaintext", bytes.fromhex("1c0d131a381b0b2c06")),
    (b"You already understood where it goes", bytes.fromhex("150e075337031c31130d1c52390f1616241c1a3b1d0d45052404001676061a741506000173")),
    (b"Last example", bytes.fromhex("00000107760a16351f190917")),
]

for i, (p, c) in enumerate(examples):
    key = xor_bytes(p, c)
    print(f"Key {i}: {key.hex()}")
    try:
        print(f"Key {i} (text): {key}")
    except:
        pass
```

Running this script revealed a repeating key: `LarsVonTrier`.

---
Level 2: Decrypting with the Repeating XOR Key
---

The challenge then presented a long hexadecimal string as "Level 2" ciphertext. Using the identified key "LarsVonTrier", I decrypted this ciphertext.

Python script `solve_level2.py`:
```python
def xor_decrypt(ciphertext, key):
    decrypted = bytearray()
    key_len = len(key)
    for i, byte in enumerate(ciphertext):
        decrypted.append(byte ^ key[i % key_len])
    return decrypted

with open("certunlp_2025_crypto_antichrist.txt", "r") as f:
    content = f.read()

parts = content.split("Now decrypt level 2:\n")
hex_cipher = parts[1].strip().replace("\n", "")
ciphertext = bytes.fromhex(hex_cipher)

key = b"LarsVonTrier"

plaintext = xor_decrypt(ciphertext, key)
print(plaintext.decode('utf-8', errors='replace'))
```

The decrypted text for Level 2 provided instructions for "Nivel 3" and new plaintext-ciphertext pairs.

Decrypted Level 2 output:
```
Nice Job. Next:

Lars Von Trier: e78e3e12b5ab712afa912317ed8a
Lara Croft: e78e3e00b5ac6c2ca1b7
La vida es bella: e78e6c17ae9c6453aacf2142efc1284f
El padrino: ee83651caf977611b391
El gran hotel budapest!: ee83650bbc85794abaca6540a28f6b15a49b7f11a78a2d

Nivel 3: e5862d0ca7c344499dc31645ce8a1c0ac297491e8e904245c9ec2f4ccfd8294de5c4275dbdda234fefda295dddea0563c7f43f66
```

---
Level 3: Autokey-like Cipher
---

The new plaintext-ciphertext pairs for Level 3 indicated a more complex encryption. Initial attempts to find a simple repeating XOR key failed, as the derived keys varied.

Analyzing the relationship `C[i] = P[i] XOR K[i]` for each pair:
- The first two bytes of the derived key (`K[0]`, `K[1]`) were consistently `0xab` and `0xef` across all examples.
    - `K[0] = P[0] XOR C[0]`
    - `K[1] = P[1] XOR C[1]`
- For `i >= 2`, a pattern emerged where `K[i]` seemed to be derived from a previous ciphertext byte XORed with one of the initial key bytes. Specifically, `K[i] = C[i-2] XOR K[i % 2]`.

This led to the full encryption/decryption algorithm:

Decryption algorithm for Level 3:
- For `i = 0`: `P[0] = C[0] XOR 0xab`
- For `i = 1`: `P[1] = C[1] XOR 0xef`
- For `i >= 2`: `P[i] = C[i] XOR (C[i-2] XOR (0xab if i is even else 0xef))`

Python script `solve_level3.py`:
```python
def decrypt_level3(hex_cipher):
    ciphertext = bytes.fromhex(hex_cipher)
    plaintext = bytearray()

    k0 = 0xab # Constant for even indices
    k1 = 0xef # Constant for odd indices

    for i in range(len(ciphertext)):
        c = ciphertext[i]
        if i == 0:
            p = c ^ k0
        elif i == 1:
            p = c ^ k1
        else:
            prev_c = ciphertext[i-2]
            k = k0 if i % 2 == 0 else k1
            p = c ^ prev_c ^ k
        plaintext.append(p)

    return plaintext

cipher_str = "e5862d0ca7c344499dc31645ce8a1c0ac297491e8e904245c9ec2f4ccfd8294de5c4275dbdda234fefda295dddea0563c7f43f66"
decrypted = decrypt_level3(cipher_str)
print(decrypted)
print(decrypted.decode('utf-8', errors='replace'))
```

Running this script yielded the following text: `Nice! Here is your flag: FMOK{Mzgfiv1h5zgzmh_XsfixS}`.

---
Final Flag Transformation: Atbash Cipher
---

The decrypted string `FMOK{Mzgfiv1h5zgzmh_XsfixS}` did not immediately look like a standard flag format (e.g., `flag{...}`). However, the prefix `FMOK` and the context of `certunlp` in the filename suggested a potential Atbash cipher.

Applying Atbash (A<->Z, a<->z) to `FMOK{Mzgfiv1h5zgzmh_XsfixS}`:
- `FMOK` became `UNLP` (Universidad Nacional de La Plata, consistent with `certunlp`).
- `Mzgfiv` became `Nature`
- `1h5` became `1s5`
- `zgzmh` became `atans`
- `XsfixS` became `ChurcH`

Python script `solve_atbash.py`:
```python
def atbash(text):
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr(ord('Z') - (ord(char) - ord('A')))
        elif 'a' <= char <= 'z':
            result += chr(ord('z') - (ord(char) - ord('a')))
        else:
            result += char
    return result

ciphertext = "FMOK{Mzgfiv1h5zgzmh_XsfixS}"
print(atbash(ciphertext))
```

The fully transformed string was `UNLP{Nature1s5atans_ChurcH}`. This phrase, "Nature is Satan's Church", is a well-known quote from the movie "Antichrist" by Lars Von Trier, which is the name of the challenge, further confirming the correctness of the decryption and transformation.
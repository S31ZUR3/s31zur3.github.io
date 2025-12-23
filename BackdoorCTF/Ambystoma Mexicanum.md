## Challenge Overview

We're given a cryptographic service that uses AES-GCM-SIV encryption. The goal is to make the service output the flag by crafting a ciphertext that, when decrypted with multiple keys, produces the message "gib me flag plis".

## Initial Analysis

Looking at the challenge code, the service provides several options:
1. Rotate key (generates a new random key)
2. Debug (shows keys, ciphertexts, and nonce)
3. Push ciphertext (allows us to submit one ciphertext)
4. Request flag (attempts to verify our message)

### The Flag Request Logic

The critical part of the code is in option 4:

```python
for i in range(4):
    key = binascii.unhexlify(KEYS[i % len(KEYS)])
    ct = binascii.unhexlify(CIPHERTEXTS[i % len(CIPHERTEXTS)])

    text = service.decrypt(ct, key)[16 * i:16 * (i+1)].decode('utf-8').strip()

    if not text or len(text) == 0:
        print("why so rude :(\n")
        exit(0)

    usertext += text

if usertext == REQUEST:  # REQUEST = "gib me flag plis"
    print(f"Damn, you are something. Here is the flag: {FLAG}\n")
```

This code:
1. Loops 4 times
2. Uses modulo to cycle through available keys and ciphertexts
3. Decrypts the ciphertext with each key
4. Extracts a different 16-byte slice from each decryption: `[0:16]`, `[16:32]`, `[32:48]`, `[48:64]`
5. Strips whitespace and concatenates all chunks
6. Checks if the result equals "gib me flag plis"

## Finding the Vulnerability

### Initial Thoughts

At first glance, this seems impossible. With 4 different keys, you'd need:
- A ciphertext that decrypts successfully with all 4 keys (AES-GCM-SIV has authentication!)
- Each decryption producing the right bytes at the right positions

### The Key Insight

The breakthrough comes from understanding the modulo operators:
- `KEYS[i % len(KEYS)]` - cycles through available keys
- `CIPHERTEXTS[i % len(CIPHERTEXTS)]` - cycles through available ciphertexts

**If we DON'T rotate the key**, `len(KEYS)` remains 1, meaning:
- `KEYS[0 % 1] = KEYS[0]`
- `KEYS[1 % 1] = KEYS[0]`
- `KEYS[2 % 1] = KEYS[0]`
- `KEYS[3 % 1] = KEYS[0]`

All iterations use the **same key**! And with one ciphertext, all iterations use the **same ciphertext** too!

## The Solution Strategy

Since all iterations use the same key and ciphertext, we just need to:
1. Create a 64-byte plaintext
2. Position our target message so each 16-byte extraction gives us the right part
3. Encrypt it with the single key
4. Handle the `.strip()` method carefully

### Handling `.strip()`

The tricky part is that `.strip()` removes **all leading and trailing whitespace**. The target message is "gib me flag plis" (16 characters with spaces between words).

If we split it as: "gib " + "me " + "flag " + "plis", the `.strip()` will remove trailing spaces, giving us "gibmeflagplis" (no spaces).

**Solution**: Split the message so spaces are in the MIDDLE of chunks, where `.strip()` won't touch them:
- Chunk 0 [0:16]: "gib m" (5 chars) + padding
- Chunk 1 [16:32]: "e fla" (5 chars) + padding
- Chunk 2 [32:48]: "g pli" (5 chars) + padding
- Chunk 3 [48:64]: "s" (1 char) + padding

After `.strip()` and concatenation: "gib m" + "e fla" + "g pli" + "s" = "gib me flag plis" ✓

## Exploit Code

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import binascii

# Get key and nonce from debug option (don't rotate keys!)
KEY_HEX = "b2e12b64da4c319a037ea801ed0b1eda"
NONCE_HEX = "358cef8f8b551be7b1a3ce2d"

TARGET = "gib me flag plis"

key = binascii.unhexlify(KEY_HEX)
nonce = binascii.unhexlify(NONCE_HEX)
aead = b""

# Create plaintext with spaces in the middle of chunks
plaintext = b'gib m           '  # -> "gib m"
plaintext += b'e fla           '  # -> "e fla"
plaintext += b'g pli           '  # -> "g pli"
plaintext += b's               '  # -> "s"

# Encrypt
cipher = AESGCMSIV(key)
ciphertext = cipher.encrypt(nonce, plaintext, aead)

print(f"Ciphertext: {ciphertext.hex()}")
```

## Exploitation Steps

1. Connect to the service: `nc remote.infoseciitr.in 4004`
2. **DON'T** choose option 1 (don't rotate keys!)
3. Choose option 2 (debug) to get the initial key and nonce
4. Run the exploit script with the key and nonce
5. Choose option 3 and paste the generated ciphertext
6. Choose option 4 to get the flag!

## Key Takeaways

1. **Modulo arithmetic matters**: The use of `% len(KEYS)` meant we could bypass the multi-key requirement entirely
2. **Read the code carefully**: The vulnerability wasn't in the crypto itself, but in how the keys were managed
3. **String manipulation edge cases**: Understanding exactly how `.strip()` works was crucial for crafting the right plaintext
4. **Sometimes the simple solution works**: Instead of trying to break AES-GCM-SIV with nonce reuse, the real solution was to avoid using multiple keys at all

## Flag

```
flag{th3_4x0lo7ls_4r3_n07_wh47_th3y_s33m}
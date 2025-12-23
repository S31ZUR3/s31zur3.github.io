crypto
## Initial Analysis

The challenge provided a file, `cipher.txt`, containing a string of text starting with `MEpHNDkw...`. The characters generally resembled Base64, but included non-standard characters like `>` and `+`, suggesting a modified or broken encoding scheme.

## Solution Walkthrough

### Step 1: Sanitization & Base64 Decoding

The first observation was that the cipher text closely resembled **Base64** but contained the character `>` instead of the standard `/`.

- **Action:** Replaced all instances of `>` with `/`.
    
- **Decoding:** Applied **Base64 Decode**.
    
- **Result:** This revealed a text string beginning with `0JG...` and containing characters like `(` and `&`, which is characteristic of Ascii85 (Base85).
    

### Step 2: Base85 Decoding

Recognizing the Ascii85 structure (commonly used in Adobe PDF formats), the output from the previous step was processed again.

- **Decoding:** Applied **Base85 Decode**.
    
- **Result:** The output was a long string of binary digits (0s and 1s).
    

### Step 3: Binary to Hex to String

The payload turned out to be an "onion" of encodings.

1. **From Binary:** The binary string was converted into text. The resulting output was a hexadecimal string (e.g., `465...`).
    
2. **From Hex:** The hexadecimal string was decoded into ASCII text.
    
3. **Result:** This produced a readable string, but it was scrambled (e.g., `FunM{zh171c13...}`).
    

### Step 4: ROT13 Shift

The scrambled text appeared to be a standard flag format with a substitution cipher applied. Given the structure, a Caesar cipher variant was suspected.

- **Decoding:** Applied **ROT13** (rotate by 13 places).
    
- **Result:** The rotation corrected the characters to reveal the final flag.
    

---

## Final Flag

`ShaZ{mu171p13_enc0d1ng3_bu7_17_1s_34sy}`
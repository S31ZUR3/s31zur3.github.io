crypto
## Overview

We are given an encryption script `encryptor.py` that transforms an input flag into an encrypted file. The encryption process is inspired by Malbolge's "crazy operation" and involves base conversions and matrix lookups. Our goal is to reverse this process to recover the original flag from the `encrypted` file.

## Encryption Analysis

Let's break down the encryption process:

1. **Input Conversion**: The input string is converted to bytes and then to a large integer `s`.
    
2. **Base-3 Conversion**: The integer `s` is treated as a base-3 number.
    
3. **Matrix Mapping**: A 3×3 matrix `o` is used to map pairs of base-3 digits to single base-9 digits:
    
    text
    

o = (
    (6, 0, 7),
    (8, 2, 1), 
    (5, 4, 3)
)

1. **Digit Processing**: The base-3 digits are processed in pairs from most significant to least significant. For each pair `(a,b)`, the value `o[a][b]` is computed and added to the output.
    
2. **Output**: The resulting base-9 number is written to the `encrypted` file as bytes.
    

The key insight is that the encryption processes the base-3 digits **in reverse order** (most significant first), which we must account for during decryption.

## Decryption Strategy

To reverse the encryption, we need to:

1. **Read the encrypted file** and convert it back to an integer `ss`.
    
2. **Convert `ss` to base-9 digits** (this gives us the output of the matrix lookups).
    
3. **Create a reverse mapping** from matrix output values to input pairs.
    
4. **Map each base-9 digit back** to its corresponding pair of base-3 digits.
    
5. **Reconstruct the base-3 number** from these digit pairs.
    
6. **Convert the base-3 number back** to bytes to recover the flag.
    

## Solution Implementation

Here's the step-by-step decryption process:

### Step 1: Read the Encrypted File

python

with open("encrypted", 'rb') as f:
    encrypted_bytes = f.read()
ss = int.from_bytes(encrypted_bytes, byteorder='big')

### Step 2: Convert to Base-9 Digits

python

base9_digits = []
temp = ss
while temp > 0:
    base9_digits.append(temp % 9)
    temp //= 9
base9_digits.reverse()

### Step 3: Create Reverse Mapping

We need to find for each output value `v`, which input pair `(i,j)` satisfies `o[i][j] = v`:

python

reverse_o = {}
for i in range(3):
    for j in range(3):
        reverse_o[o[i][j]] = (i, j)

This gives us:

- `0 → (0,1)`
    
- `1 → (1,2)`
    
- `2 → (1,1)`
    
- `3 → (2,2)`
    
- `4 → (2,1)`
    
- `5 → (2,0)`
    
- `6 → (0,0)`
    
- `7 → (0,2)`
    
- `8 → (1,0)`
    

### Step 4: Map Base-9 Digits to Base-3 Pairs

python

pairs = [reverse_o[d] for d in base9_digits]

### Step 5: Reconstruct Base-3 Number

The encryption processes digits from most significant to least significant, so we need to carefully reconstruct the base-3 number:

python

# The pairs represent: (most_significant_digit, least_significant_digit), 
# (second_most_significant, second_least_significant), etc.
n = len(pairs) * 2
base3_digits = [0] * n

for i, (l, r) in enumerate(pairs):
    base3_digits[i] = l           # Fill from left (most significant)
    base3_digits[n-1-i] = r       # Fill from right (least significant)

# Convert base-3 digits to integer
s_decrypted = 0
for digit in base3_digits:
    s_decrypted = s_decrypted * 3 + digit

### Step 6: Convert to Bytes and Decode

python

byte_length = (s_decrypted.bit_length() + 7) // 8
flag_bytes = s_decrypted.to_bytes(byte_length, byteorder='big')
flag = flag_bytes.decode(errors='ignore')

## Final Script
 
``` python
import math

def decrypt():
    # Read the encrypted file
    with open("encrypted", 'rb') as f:
        encrypted_bytes = f.read()
    
    # Convert to integer
    ss = int.from_bytes(encrypted_bytes, byteorder='big')
    
    # The mapping matrix used in encryption
    o = (
        (6, 0, 7),
        (8, 2, 1),
        (5, 4, 3)
    )
    
    # Create reverse mapping: from output value to (i,j) coordinates
    reverse_o = {}
    for i in range(3):
        for j in range(3):
            reverse_o[o[i][j]] = (i, j)
    
    # Convert integer ss to base-9 digits
    if ss == 0:
        base9_digits = [0]
    else:
        base9_digits = []
        temp = ss
        while temp > 0:
            base9_digits.append(temp % 9)
            temp //= 9
        base9_digits.reverse()  # now most significant first
    
    # Now, for each base-9 digit, get the pair (l, r)
    pairs = []
    for digit in base9_digits:
        if digit not in reverse_o:
            raise ValueError(f"Invalid digit {digit} in base-9 representation")
        pairs.append(reverse_o[digit])
    
    # Number of pairs
    m = len(pairs)
    n = 2 * m  # number of base-3 digits
    
    # Create an array for base-3 digits
    base3_digits = [0] * n
    for i, (l, r) in enumerate(pairs):
        base3_digits[i] = l
        base3_digits[n - 1 - i] = r
    
    # Convert base-3 digits to integer
    s_decrypted = 0
    for digit in base3_digits:
        s_decrypted = s_decrypted * 3 + digit
    
    # Convert integer to bytes
    if s_decrypted == 0:
        byte_length = 1
    else:
        byte_length = (s_decrypted.bit_length() + 7) // 8
    
    flag_bytes = s_decrypted.to_bytes(byte_length, byteorder='big')
    
    return flag_bytes.decode(errors='ignore')

if __name__ == '__main__':
    flag = decrypt()
    print(f"Recovered flag: {flag}")
```
## Flag Recovery

Running this decryption process on the provided `encrypted` file reveals the flag:

pctf{a_l3ss_cr4zy_tr1tw1s3_op3r4ti0n_f37d4b}

[[PatriotCTF-2025]]
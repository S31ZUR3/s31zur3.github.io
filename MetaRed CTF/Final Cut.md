rev
## Overview
The challenge provided a 64-bit ELF binary `final_cut`. When executed, it displayed a "Rendering" message and attempted to calculate an "Optimal Cut Score" before hanging indefinitely. The goal was to recover the flag, which was encrypted within the binary.

## Analysis

### Static Analysis
Using `file` and `strings`, we identified it as a standard Linux executable. Strings like "AES-128 Decryption Projector", "Projector Malfunction: Key Error", and "Calculating optimal cut" suggested that the program was performing a calculation to derive a decryption key.

Disassembling with `objdump` (or using a decompiler like Ghidra/IDA) revealed the main logic:
1.  **Data loading**: The program loads two arrays of integers from the `.rodata` section. These correspond to "weights" (runtime) and "values" (scene score).
2.  **Knapsack Problem**: The "Calculating optimal cut" phase implements a recursive solution to the 0/1 Knapsack Problem.
    *   Capacity (Max Runtime): 240
    *   Number of items (Scenes): 100
    *   The recursive implementation has exponential time complexity O(2^n), causing the program to hang.
3.  **Key Generation**: The result of this calculation (the optimal score) is used to construct an AES-128 key.
    *   The key buffer is 16 bytes initialized to zero.
    *   The 64-bit integer result is written to the first 8 bytes (little-endian).
4.  **Decryption**: The binary uses OpenSSL's `AES_decrypt` (ECB mode) to decrypt a stored blob of data using the generated key.

### Extraction
We identified the offsets for the relevant data structures in the binary:
*   **Weights Array**: Offset `0x2020` (Size: 100 integers)
*   **Values Array**: Offset `0x21C0` (Size: 100 integers)
*   **Encrypted Flag**: Offset `0x2360` (Size: 48 bytes)

## Solution

Instead of waiting for the slow recursive algorithm to finish, we implemented the Knapsack solver using Dynamic Programming (DP). This reduces the complexity to O(n * W), which runs instantly.

### Script (`solve.py`)

```python
import struct
from Crypto.Cipher import AES

def solve():
    with open('final_cut', 'rb') as f:
        # Extract Weights
        f.seek(0x2020)
        weights_data = f.read(400) # 100 integers * 4 bytes
        weights = struct.unpack('<100i', weights_data)

        # Extract Values
        f.seek(0x21C0)
        values_data = f.read(400)
        values = struct.unpack('<100i', values_data)
                                                                                                    # Extract Encrypted Flag                                                                    f.seek(0x2360)
        encrypted_flag = f.read(48)

    capacity = 240                                                                              n = 100

    # Knapsack Dynamic Programming Solution
    # dp[w] = max value with capacity w
    dp = [0] * (capacity + 1)

    for i in range(n):
        w = weights[i]
        v = values[i]                                                                               for j in range(capacity, w - 1, -1):                                                            dp[j] = max(dp[j], dp[j-w] + v)
    optimal_score = dp[capacity]
    print(f"Optimal Score: {optimal_score}")

    # Construct Key
    # Key is 16 bytes: [Score (8 bytes)][Zero Padding (8 bytes)]
    key = struct.pack('<Q', optimal_score) + b'\x00' * 8

    print(f"Key (hex): {key.hex()}")

    # Decrypt
    try:                                                                                            cipher = AES.new(key, AES.MODE_ECB)                                                         decrypted = cipher.decrypt(encrypted_flag)                                                  print(f"Decrypted: {decrypted.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"Decryption failed: {e}")                                                                                                                                                if __name__ == "__main__":
    solve()
```

## Result
Running the script yields the optimal score and decrypts the flag:

*   **Optimal Score**: `17452999`
*   **Key**: `c74f0a01000000000000000000000000`
*   **Flag**: `UNLP{DyNam1C_Pr0gRamm1nG_w1Ns_0sC4rs}`
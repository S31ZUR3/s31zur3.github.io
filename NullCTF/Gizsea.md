crypto
## Challenge Overview
The challenge provides a server implementing a custom block cipher encryption scheme labeled "Gizsea". We are given the source code (`server.zig`) and the ability to interact with the server via netcat. The server allows us to:
1. Encrypt arbitrary plaintext (hex).
2. Decrypt arbitrary ciphertext (hex), with a validation check.
3. Get the encrypted flag.

The validation check (`isValid`) prevents us from decrypting any ciphertext that contains blocks identical to the encrypted flag blocks.

## Crypto Analysis

### Encryption Scheme
The encryption function `sch3m3Encrypt` uses AES-128 in a custom feedback mode.
For a plaintext block $P_i$ and ciphertext block $C_i$:

$$C_i = \text{AES\_DEC}(key, P_i) \oplus P_{i-1}$$

Where $P_{-1} = IV$.
Note that it uses AES **Decryption** primitive for the encryption process.

### Decryption Scheme
The decryption function `sch3m3Decrypt` reverses the operation:

$$P_i = \text{AES\_ENC}(key, C_i \oplus P_{i-1})$$

This confirms the relationship. If we know $C_i$ and $P_{i-1}$, we can recover $P_i$ by calculating $X = C_i \oplus P_{i-1}$ and then applying the AES Encryption primitive to $X$.

## Vulnerability                                                                                                                                                                        The vulnerability stems from the combination of a chosen-plaintext attack (CPA) and a chosen-ciphertext attack (CCA), despite the filter on the decryption oracle.

### 1. IV Recovery                                                                          Since the IV is generated randomly at startup and reused for the session, we can recover it using the Encryption Oracle.
If we encrypt two blocks of zeros ($P_0 = 0, P_1 = 0$):
$$C_0 = \text{AES\_DEC}(0) \oplus IV$$
$$C_1 = \text{AES\_DEC}(0) \oplus P_0 = \text{AES\_DEC}(0) \oplus 0 = \text{AES\_DEC}(0)$$

By XORing them:
$$C_0 \oplus C_1 = (\text{AES\_DEC}(0) \oplus IV) \oplus \text{AES\_DEC}(0) = IV$$

### 2. Flag Recovery (Oracle Manipulation)
We have the encrypted flag blocks $C_{flag\_0}, C_{flag\_1}, \dots$.
We want to recover $P_{flag\_0}, P_{flag\_1}, \dots$.

For any block $i$, we know $P_{flag\_i} = \text{AES\_ENC}(C_{flag\_i} \oplus P_{flag\_(i-1)})$.
(For $i=0$, $P_{flag\_(-1)} = IV$, which we just recovered).

We cannot simply ask the decryption oracle to decrypt $C_{flag\_i}$ because of the `isValid` check. However, we can construct a **different** ciphertext that results in the same input to the underlying AES primitive.
                                                                                            We construct a 2-block ciphertext $C'_0 || C'_1$ to send to the decryption oracle:          1.  **Select $C'_0$**: Choose a random 16-byte block that is **not** present in the encrypted flag.
2.  **Get $P'_0$**: We can query the decryption oracle with just $C'_0$ (or calculate it as part of the chain) to find what it decrypts to.                                                 $$P'_0 = \text{AES\_ENC}(C'_0 \oplus IV)$$
3.  **Calculate $C'_1$**: We want the second block's decryption to output our target flag block $P_{flag\_i}$.                                                                              The decryption logic for the second block is:                                               $$P'_1 = \text{AES\_ENC}(C'_1 \oplus P'_0)$$
    We want $P'_1 = P_{flag\_i}$, which means inputs to AES must match:
    $$C'_1 \oplus P'_0 = C_{flag\_i} \oplus P_{flag\_(i-1)}$$
    Solving for $C'_1$:
    $$C'_1 = C_{flag\_i} \oplus P_{flag\_(i-1)} \oplus P'_0$$

4.  **Verify**: Check if our calculated $C'_1$ happens to be in the encrypted flag blocks. If it is (collision), pick a new random $C'_0$ and retry.
5.  **Exploit**: Send $C'_0 || C'_1$ to the decryption oracle. The returned second block of plaintext is the flag block $P_{flag\_i}$.

## Solution Script Summary
1. Connect to the server.
2. Retrieve the Encrypted Flag.
3. Encrypt 32 bytes of zeros to recover the IV.
4. Iterate through each block of the encrypted flag:
   - Generate random $C'_0$.                                                                   
   - Query oracle to get $P'_0$.
   - Calculate required $C'_1$.
   - Query oracle with $C'_0 || C'_1$ to get the flag block.
   - Update $P_{prev}$ for the next iteration.                                              
5. Print the flag.
**Flag:** `nullctf{z1g_z4g_cr7pt0_fl1p_fl0p}`
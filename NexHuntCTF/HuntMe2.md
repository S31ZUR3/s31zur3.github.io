Reverse Engineering
1. Initial Analysis (FUN_004013df)

The main logic in FUN_004013df (the entry point after setup) showed that user input was read and then passed to a function named FUN_0040132a for validation. Success required FUN_0040132a to return a non-zero value.
2. Core Validation Logic (FUN_0040132a)

The analysis of FUN_0040132a revealed the core encryption scheme:

    Length Check: The input string must be exactly 32 bytes long (sVar2 == 0x20).

    Decryption Formula: The function iterated from i=0 to 31, comparing the input byte against a decryption key stream and a hardcoded encoded array. The successful condition was derived as:
    Input[i]=E[i]⊕KeyByte[i]

    Where:

        E[i] is the i-th byte of the 32-byte encoded array at DAT_00402060.

        KeyByte[i] is the result of the key generation function FUN_00401239(i).

3. Key Generation Logic (FUN_00401239)

The key stream was dynamically generated using the input index i and five 7-byte arrays (DAT_00402020 to DAT_0040203c).

    Internal Accumulator (local_9): The function iterated five times (local_10=0…4):

        It calculated an index local_1c using a formula involving local_10 and the input index i:
        local_1c=((local_102)+((local_10+1)×i)+3)(mod7)

        It XORed the accumulator with the byte from the key material array M[local_10][local_1c].

        It then applied a custom bitwise rotation/mixing operation:
        local_9=((XOR_Result≫7)∣(XOR_Result×2))(mod256)

    Final Key Mixer: The accumulator (local_9) and the index i were passed to FUN_00401201 to produce the final key byte.

4. Final Key Mixer (FUN_00401201)

This function completed the key generation with a final mixing step:

    param_1=(local_9⊕(local_9≪3))(mod256)
    KeyByte[i]=(param_1⊕(param_1≫5)⊕(i×0x3d))(mod256)

5. Data Extraction (Ghidra)

The final step involved extracting the hardcoded data from the binary's data section:
Data Type       Address Hexadecimal Values
Encoded Flag (E) (32 bytes)     DAT_00402060    F8 98 76 FB C9 0A 03 0D 44 3D 6B A6 C3 25 A8 60 FB 57 6C F3 A1 F0 CF 61 E6 E4 45 16 0E 18 3E 27
Key Material (M) (5 x 7 bytes)  DAT_00402020    A8 C5 83 A0 42 2C 01 CB 32 20 F3 CF 65 BC 13 79 B2 29 74 61 E7 A7 68 76 0A 4E 39 43 F1 CD 12 B2 7D 0B 2D

6. Decryption and Solution

A Python script was used to reverse the encryption logic:

 ```python
 ENCODED_FLAG = [
    0xF8, 0x98, 0x76, 0xFB, 0xC9, 0x0A, 0x03, 0x0D, 0x44, 0x3D, 0x6B, 0xA6, 0xC3, 0x25, 0xA8, 0x60,
    0xFB, 0x57, 0x6C, 0xF3, 0xA1, 0xF0, 0xCF, 0x61, 0xE6, 0xE4, 0x45, 0x16, 0x0E, 0x18, 0x3E, 0x27
] # 32 bytes from DAT_00402060

KEY_MATERIAL = [
    [0xA8, 0xC5, 0x83, 0xA0, 0x42, 0x2C, 0x01], # DAT_00402020
    [0xCB, 0x32, 0x20, 0xF3, 0xCF, 0x65, 0xBC], # DAT_00402027
    [0x13, 0x79, 0xB2, 0x29, 0x74, 0x61, 0xE7], # DAT_0040202E
    [0xA7, 0x68, 0x76, 0x0A, 0x4E, 0x39, 0x43], # DAT_00402035
    [0xF1, 0xCD, 0x12, 0xB2, 0x7D, 0x0B, 0x2D]  # DAT_0040203C
]

# --- 2. FUN_00401201 Implementation ---
def FUN_00401201(param_1: int, param_2: int) -> int:
    """byte FUN_00401201(byte param_1,char param_2)"""
    # param_1 = param_1 ^ param_1 << 3; (Masked to 8-bit)
    param_1 = (param_1 ^ (param_1 << 3)) & 0xFF

    # return param_1 ^ param_1 >> 5 ^ param_2 * '=';
    # '= (0x3D)'
    result = param_1 ^ (param_1 >> 5) ^ (param_2 * 0x3D)
    return result & 0xFF

# --- 3. FUN_00401239 Implementation ---
def FUN_00401239(param_1: int) -> int:
    """undefined1 FUN_00401239(int param_1)"""
    local_9 = 0 # byte local_9

    for local_10 in range(5):
        # local_1c = (local_10 * local_10 + (local_10 + 1) * param_1 + 3) % 7;
        local_1c = ((local_10 * local_10) + ((local_10 + 1) * param_1) + 3) % 7

        local_18_local_1c = KEY_MATERIAL[local_10][local_1c]

        # local_9 ^ local_18[local_1c]
        xor_result = local_9 ^ local_18_local_1c

        # local_9 = (xor_result) >> 7 | (xor_result) * '\x02'; (0x02)
        # This is a bit-wise mix, potentially a rotate left by 1.
        local_9 = ((xor_result >> 7) | (xor_result * 2)) & 0xFF

    # uVar1 = FUN_00401201(local_9,param_1);
    return FUN_00401201(local_9, param_1)


# --- 4. Decrypting the Flag ---
FLAG_BYTES = []
for i in range(32):
    encoded_byte = ENCODED_FLAG[i]
    key_byte = FUN_00401239(i)

    # InputByte = EncodedByte XOR KeyByte
    flag_byte = encoded_byte ^ key_byte
    FLAG_BYTES.append(flag_byte)

# Convert bytes to the final ASCII string
final_flag = bytes(FLAG_BYTES).decode('ascii')

# --- 5. Output ---
print("--- Calculated Solution ---")
print(f"Required Input Length: 32 characters")
print(f"Decrypted Flag (Hex):   {' '.join(f'{b:02X}' for b in FLAG_BYTES)}")
print(f"Decrypted Flag (ASCII): {final_flag}")
 ```


nexus{f0ll0w_7h3_ch4ng1ng_7r41l}
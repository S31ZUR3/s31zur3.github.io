rev

The challenge is a Rust program that takes a 32-byte string as input, applies a series of six transformations to it, and compares the result to a hardcoded target value. To find the flag, we must reverse these transformations, starting from the target value, to recover the original input.

The script `main.rs` helpfully describes each transformation and notes that they are all bijections, meaning they are all reversible.

The transformations are applied in this order:
1. `apply_quantum_cipher_v2`: XORs bytes with a 5-byte rotating key.
2. `apply_stellar_rotation`: Rotates bytes left based on their position.
3. `apply_spatial_transposition`: Swaps adjacent byte pairs.
4. `apply_gravitational_shift_v2`: Subtracts a constant from each byte.
5. `apply_temporal_inversion`: Reverses bytes in 5-byte chunks.
6. `apply_coordinate_calibration_v2`: XORs each byte with its index squared.

To solve the challenge, we must apply the inverse of these operations in the reverse order (6 down to 1) to the `TARGET` array.

The inverse operations are:
1. **Reverse Coordinate Calibration**: XOR is its own inverse, so we XOR each byte with its index squared.
2. **Reverse Temporal Inversion**: Reversing is its own inverse, so we reverse the bytes in 5-byte chunks again.
3. **Reverse Gravitational Shift**: The inverse of subtraction is addition. We add the `MAGIC_SUB` constant to each byte.
4. **Reverse Spatial Transposition**: Swapping is its own inverse. We swap adjacent pairs again.
5. **Reverse Stellar Rotation**: The inverse of a left rotation is a right rotation. We rotate each byte right by the same amount it was rotated left.
6. **Reverse Quantum Cipher**: XOR is its own inverse. We XOR each byte with the corresponding key byte again.

A solver program was created (`solve.rs`) that contained the `TARGET` data and the inverse functions. Running this program decrypts the `TARGET` array and prints the flag.

Flag: PCTF{Y0U_F0UND_TH3_P1R4T3_B00TY}
[[PatriotCTF-2025]]
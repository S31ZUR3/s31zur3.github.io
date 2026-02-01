#Rev 
## Challenge Overview
The challenge provides a custom virtual machine (`vm`) and a bytecode file (`binary.bin`). The VM takes a 16-byte hexadecimal input and determines if it is the correct key to unlock the flag.

## Initial Analysis
Running the VM with dummy input returns "Wrong!".
```bash
./vm binary.bin <<< "00000000000000000000000000000000"
```
Examination of the `vm` binary reveals a dispatch table at `0x4040c0` and several `op_*` functions, indicating a stack-based architecture.

## VM Architecture
Through disassembly of `vm_run` and `init_dispatch_table`, the following opcode mapping was established:

| Opcode | Function | Description |
|--------|----------|-------------|
| 0x01 | `op_push` | Push byte from bytecode to stack |
| 0x04 | `op_store` | Store byte to VM memory |
| 0x06 | `op_load` | Load byte from VM memory |
| 0x12 | `op_rol` | Rotate left |
| 0x15 | `op_permute` | Permute 8 bytes using a table |
| 0x20 | `op_push16` | Push 16-bit word from bytecode |
| 0x21 | `op_pop` | Pop value from stack |
| 0x24 | `op_store16` | Store 16-bit word to memory |
| 0x40 | `op_xor` | XOR top two stack values |
| 0x41 | `op_decrypt` | Perform block cipher transformation |
| 0x42 | `op_input` | Read 32 hex characters into memory |
| 0x3F | `op_halt` | Stop execution |

### Memory Layout
- `0x000`: Stack space.
- `0x100`: Main data memory (user input stored here).
- `0x500`: S-box.
- `0x600`: Permutation table.
- `0x910`: Instruction Pointer (IP).
- `0x912`: Stack Pointer (SP).

## Cryptographic Algorithm
The `op_decrypt` function (found at opcode `0x41`) implements the core block cipher. It processes data in 8-byte blocks over 4 rounds.

Each round consists of:
1. **SubBytes**: S-box substitution.
2. **AddRoundKey**: XOR with `Key1`.
3. **Rotate**: Bitwise left rotation of each byte by values in `Key2`.
4. **Permutation**: Rearranging bytes according to the table at `0x600`.
5. **Linear Layer (MixColumns)**: A custom bitwise transformation:
   `new_b[i] = b[i] ^ rol(b[(i+1)%8], (i+1)%8) ^ b[(i+3)%8]`

## Data Extraction
The bytecode in `binary.bin` stores the S-box, keys, and target bytes XORed with constants:
- **S-box**: XORed with `0x5a`.
- **Permutation Table**: XORed with `0x33`.
- **Key1**: XORed with `0x7f`.
- **Key2**: XORed with `0x1d`.
- **Target Ciphertext**: XORed with `0x42`.

Extraction revealed:
- `Permutation Table`: `[2, 5, 0, 7, 4, 1, 6, 3]`
- `Target`: `10e08e4e669108f8478c5b3a31c15ada`

## Solving
To recover the flag, a solver was written to invert the 4 rounds of the block cipher:
1. **Invert Linear Layer**: Constructed a 64x64 matrix representing the bitwise dependencies and inverted it over GF(2).
2. **Invert Permutation**: Applied the inverse of the permutation table.
3. **Invert Rotation**: Rotated bits right using `Key2`.
4. **Invert XOR**: XORed with `Key1`.
5. **Invert SubBytes**: Applied the inverse S-box.

### Flag Recovery
Running the inverse transformation on the target bytes yielded:
`DEADBEEFCAFEBABE1337C0DEF00DFACE`

Providing this input to the VM:
```bash
./vm binary.bin <<< "DEADBEEFCAFEBABE1337C0DEF00DFACE"
```
Result: `esch{br0k3_th3_vm_4ndd_th3_c1pher!!}`
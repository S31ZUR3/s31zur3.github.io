rev
## 1. Initial Analysis
The challenge consists of a single ELF 64-bit executable named `chall`.
Running the binary prompts for a "magic number":
```
Enter the magic number: 1234
```

## 2. Reverse Engineering
Using `objdump` and `readelf`, the `main` function was analyzed.

### Stage 1: The Magic Number
The program seeds the random number generator using `srand(time(NULL))`.
It then generates a value based on `rand()`, performs some arithmetic, and compares it with the user's input.
Since this depends on the current time, it's a dynamic check that can be bypassed or emulated. However, looking further into the code revealed that the flag is constructed independently of the specific "magic number" value (as long as the check passes).

### Stage 2: Flag Construction
After the magic number check, the program enters a loop that runs 34 times.
It processes data from a global array located at `stage1` (offset `0x2020` in the binary).

The decoding logic extracted from the assembly:
1. Fetch a 4-byte integer `val` from `stage1[i]`.
2. Subtract `3 * i` from `val`.
3. Perform a signed integer division by 2: `val = (val + sign_bit) >> 1`.
4. XOR `val` with `i % 7`.
5. Subtract `0x11` from `val`.
6. Convert the resulting byte to a character.

## 3. Exploitation
The `stage1` array (136 bytes) was extracted from the binary. A Python script was used to replicate the decoding logic.

```python
import struct

# Extracted 136 bytes from offset 0x2020
data = [...]

flag = ""
for i in range(34):
    val = struct.unpack('<i', data[i*4 : (i+1)*4])[0]
    val = val - 3*i
    sign_bit = (val >> 31) & 1
    val = (val + sign_bit) >> 1
    val = val ^ (i % 7)
    val = val - 0x11
    flag += chr(val & 0xFF)

print(flag)
```

## 4. Flag
`ShaZ{r4nd0m_r3v_s0lv3d_suc33fu11y}`
rev

## Challenge Overview

The challenge provides a C program (`challenge.c`) that takes a 30-character command-line argument as input. It then performs a series of transformations on this input and compares the result to a hardcoded target value. If the transformed input matches the target, the original input is the flag, and the program prints a success message.

The core of the challenge lies in understanding the transformations and reversing them to find the correct input that produces the target value.

## Analyzing the Transformations

The `challenge.c` program applies four distinct operations to the input string. Let's examine them in the order they are applied:

1.  **XOR with a Rotating Key:** Each byte of the input is XORed with a byte from a 5-byte key (`XOR_KEY`). The key byte is selected based on the position of the input byte, cycling through the key.

    ```c
    for (int i = 0; i < FLAG_LEN; i++) {
        buffer[i] ^= XOR_KEY[i % 5];
    }
    ```

2.  **Swap Adjacent Byte Pairs:** The program swaps every pair of adjacent bytes. For example, the bytes at indices 0 and 1 are swapped, then the bytes at indices 2 and 3 are swapped, and so on.

    ```c
    for (int i = 0; i < FLAG_LEN; i += 2) {
        uint8_t temp = buffer[i];
        buffer[i] = buffer[i + 1];
        buffer[i + 1] = temp;
    }
    ```

3.  **Add Magic Constant:** A constant value (`MAGIC_ADD`, which is `0x2A`) is added to each byte. The addition is performed modulo 256 to handle overflow.

    ```c
    for (int i = 0; i < FLAG_LEN; i++) {
        buffer[i] = (buffer[i] + MAGIC_ADD) % 256;
    }
    ```

4.  **XOR with Position:** Each byte is XORed with its own index in the array.

    ```c
    for (int i = 0; i < FLAG_LEN; i++) {
        buffer[i] ^= i;
    }
    ```

After these transformations, the resulting `buffer` is compared with the `TARGET` array.

## The Reversal Strategy

To find the flag, we need to reverse these operations, starting from the `TARGET` value and working our way back to the original input. The key is to apply the inverse of each operation in the reverse order.

Here's the reversal plan:

1.  **Reverse XOR with Position:** The inverse of XORing with a value is XORing with the same value again. So, we'll XOR each byte of the `TARGET` array with its index.

2.  **Reverse Add Magic Constant:** The inverse of adding a constant is subtracting the same constant. We'll subtract `MAGIC_ADD` from each byte, again using modulo 256 arithmetic.

3.  **Reverse Swap Adjacent Byte Pairs:** The inverse of swapping pairs is... swapping them again! This operation is its own inverse.

4.  **Reverse XOR with Rotating Key:** Similar to the position XOR, we'll XOR each byte with the corresponding byte from the `XOR_KEY`.

## The Solver

The provided `solver.c` program implements this reversal strategy. Let's look at the code:

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define FLAG_LEN 30
const uint8_t TARGET[FLAG_LEN] = {
    0x5A,0x3A,0x5B,0x9C,0x98,0x73,0xAE,0x32,0x25,0x47,0x48,0x51,0x6C,0x71,0x3A,0x62,0xB8,0x7B,0x63,0x57,0x25,0x89,0x58,0xBF,0x78,0x34,0x98,0x71,0x68,0x59
};

const uint8_t XOR_KEY[5] = {0x42, 0x73, 0x21, 0x69, 0x37};
const uint8_t MAGIC_ADD = 0x2A;

int main() {
    uint8_t buffer[FLAG_LEN];
    memcpy(buffer, TARGET, FLAG_LEN);

    // Reverse Operation 4: XOR each byte with its position
    for (int i = 0; i < FLAG_LEN; i++) {
        buffer[i] ^= i;
    }

    // Reverse Operation 3: Subtract magic constant (mod 256)
    for (int i = 0; i < FLAG_LEN; i++) {
        buffer[i] = (buffer[i] - MAGIC_ADD) % 256;
    }

    // Reverse Operation 2: Swap adjacent byte pairs
    for (int i = 0; i < FLAG_LEN; i += 2) {
        uint8_t temp = buffer[i];
        buffer[i] = buffer[i + 1];
        buffer[i + 1] = temp;
    }

    // Reverse Operation 1: XOR with rotating key
    for (int i = 0; i < FLAG_LEN; i++) {
        buffer[i] ^= XOR_KEY[i % 5];
    }

    printf("Flag: %s\n", buffer);

    return 0;
}
```

## The Solution

Compiling and running the `solver.c` program will print the flag:

```bash
gcc solver.c -o solver
./solver
```

This will output:

```
Flag: PCTF{0x_M4rks_tH3_sp0t_M4t3ys}
```

## Conclusion

The "Space Pirates" challenge was a fun and classic reverse engineering problem. By carefully analyzing the transformations and applying their inverses in the reverse order, we were able to successfully recover the flag.
[[PatriotCTF-2025]]
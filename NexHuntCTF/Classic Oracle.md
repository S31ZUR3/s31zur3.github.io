Cryptography
### 1. Challenge Overview

We are provided with a network service (`nc ctf.nexus-security.club 4338`) acting as an RSA oracle. The oracle has a fixed modulus N and a fixed secret flag m. Every time we query the oracle, it generates a fresh public exponent e and returns the encrypted flag c=me(modN).

We are allowed 10 queries.

### 2. Reconnaissance & Analysis

Connecting to the server reveals the following behavior:

- **Modulus (N):** Stays constant across all queries.
    
- **Message (m):** The flag is constant.
    
- **Exponent (e):** Changes with every query (e.g., `4344149288...`, `3817192702...`).
    

This setup immediately suggests a **Common Modulus Attack**.

### 3. The Vulnerability

In RSA, if the same message m is encrypted with the same modulus N but different exponents e1​,e2​, we can recover m if gcd(e1​,e2​)=1.

Using the **Extended Euclidean Algorithm**, we can find integers u,v such that:

u⋅e1​+v⋅e2​=gcd(e1​,e2​)

We can then combine the ciphertexts c1​,c2​ to find the message raised to the power of the GCD:

cnew​≡c1u​⋅c2v​(modN)

cnew​≡(me1​)u⋅(me2​)v(modN)

cnew​≡mu⋅e1​+v⋅e2​≡mgcd(e1​,e2​)(modN)

### 4. The "Twist": GCD = 3

During the attack, we observed that combining multiple exponents did **not** result in an exponent of 1. Instead, the GCD converged to **3**.

Plaintext

```
[*] Fetching next pair to reduce exponent...
    Got new e: 180026049740450541
[*] Combined! New effective exponent: 3
...
```

This means we recovered cfinal​=m3(modN).

Since the flag is a short string (likely < 100 bytes), its cubic value m3 is significantly smaller than the 1024-bit modulus N. Therefore, no modular wraparound occurred:

cfinal​=m3

To get the flag, we simply calculate the integer cube root: m=3cfinal​![](data:image/svg+xml;utf8,<svg%20xmlns="http://www.w3.org/2000/svg"%20width="400em"%20height="1.08em"%20viewBox="0%200%20400000%201080"%20preserveAspectRatio="xMinYMin%20slice"><path%20d="M95,702c-2.7,0,-7.17,-2.7,-13.5,-8c-5.8,-5.3,-9.5,-10,-9.5,-14c0,-2,0.3,-3.3,1,-4c1.3,-2.7,23.83,-20.7,67.5,-54c44.2,-33.3,65.8,-50.3,66.5,-51c1.3,-1.3,3,-2,5,-2c4.7,0,8.7,3.3,12,10s173,378,173,378c0.7,0,35.3,-71,104,-213c68.7,-142,137.5,-285,206.5,-429c69,-144,104.5,-217.7,106.5,-221l0%20-0c5.3,-9.3,12,-14,20,-14H400000v40H845.2724s-225.272,467,-225.272,467s-235,486,-235,486c-2.7,4.7,-9,7,-19,7c-6,0,-10,-1,-12,-3s-194,-422,-194,-422s-65,47,-65,47zM834%2080h400000v40h-400000z"></path></svg>)​.

### 5. Solution Script

Here is the final python script using `pwntools` to automate the attack.

Python

```
from pwn import *
from Crypto.Util.number import long_to_bytes

HOST = 'ctf.nexus-security.club'
PORT = 4338

# Extended Euclidean Algorithm
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

# Integer Cube Root
def integer_root(n, k):
    low = 0
    high = n
    while low < high:
        mid = (low + high + 1) // 2
        if mid ** k <= n:
            low = mid
        else:
            high = mid - 1
    return low

def solve():
    io = remote(HOST, PORT)
    
    # 1. Get first ciphertext pair
    io.sendlineafter(b'>', b'1')
    io.recvuntil(b'e = ')
    curr_e = int(io.recvline().strip())
    io.recvuntil(b'c = ')
    curr_c = int(io.recvline().strip())
    io.recvuntil(b'n = ')
    n = int(io.recvline().strip())
    
    print(f"[+] Started with exponent: {curr_e}")

    # 2. Collect more pairs to reduce GCD
    for _ in range(9):
        if curr_e == 3:
            print("[!] Exponent converged to 3. Stopping loop.")
            break
            
        io.sendline(b'1')
        try:
            io.recvuntil(b'e = ')
            next_e = int(io.recvline().strip())
            io.recvuntil(b'c = ')
            next_c = int(io.recvline().strip())
            io.recvuntil(b'n = ')
            io.recvline() 
        except:
            break

        # Calculate Bezout coefficients
        g, u, v = egcd(curr_e, next_e)
        
        # Combine ciphertexts: c_new = c1^u * c2^v mod n
        # This results in m^gcd(e1, e2)
        term1 = pow(curr_c, u, n)
        term2 = pow(next_c, v, n)
        curr_c = (term1 * term2) % n
        curr_e = g
        
        print(f"[*] Reduced exponent to: {curr_e}")

    # 3. Recover Flag
    if curr_e == 3:
        print("[+] Calculating cube root...")
        m_int = integer_root(curr_c, 3)
        print(f"[+] FLAG: {long_to_bytes(m_int).decode()}")
    elif curr_e == 1:
        print(f"[+] FLAG: {long_to_bytes(curr_c).decode()}")
    else:
        print("[-] Failed to reduce exponent sufficiently.")

    io.close()

if __name__ == "__main__":
    solve()
```

### 6. Result

Running the script quickly reduces the exponent to 3, computes the cube root, and prints the flag.

**Flag:** `nexus{GCD_0f_3xp0n3nts_R0cks}`
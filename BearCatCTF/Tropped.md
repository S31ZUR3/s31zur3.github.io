#Cryptography 
### Overview

This challenge features a custom key exchange protocol built on the **Tropical Semiring** (specifically min-plus algebra). We are given a script `tropped.py` that defines this custom matrix multiplication and an `output.txt` file containing the public parameters and encrypted characters.

In standard linear algebra, matrix multiplication relies on addition and multiplication. In min-plus algebra, addition is replaced by the $\min$ operation, and multiplication is replaced by standard addition.

For two matrices $A$ and $B$, their tropical product $C = A \otimes B$ is defined as:

$$C_{i,j} = \min_{k} (A_{i,k} + B_{k,j})$$

### The Vulnerability

The protocol simulates a Diffie-Hellman-style key exchange:

1. A public $64 \times 64$ matrix $M$ is shared.
    
2. Alice generates a secret row vector $a$ and publishes $aM = a \otimes M$.
    
3. Bob generates a secret column vector $b$ and publishes $Mb = M \otimes b$.
    
4. The shared secret is $V = a \otimes M \otimes b$.
    
5. A character is encrypted using $V$: `pt_byte = chr((V % 32) ^ ord(enc_byte))`.
    

We have intercepted $M$, $aM$, and $Mb$. To decrypt the flag, we need to recover the shared secret $V$. Because of the properties of min-plus algebra, we can mount a known-plaintext attack to recover an equivalent private key for Alice.
### The Exploit Script

Here is the Python script to parse `output.txt`, compute the equivalent key $\tilde{a}$, derive the shared secret, and decrypt the flag.

Python

```python
import json
def solve():
    with open('output.txt', 'r') as f:
        lines = f.readlines()
    M = json.loads(lines[0])['M']
    n = len(M)
    flag = ""
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        aM = data['aM'][0]
        Mb = [row[0] for row in data['Mb']]
        enc_char = data['enc_char']
        a_star = [max(aM[j] - M[k][j] for j in range(n)) for k in range(n)]
        V = min(a_star[k] + Mb[k] for k in range(n))
        flag += chr((V % 32) ^ ord(enc_char))
    print(flag)
if __name__ == '__main__':
    solve()
```

Flag:`BCCTF{1_h4T3_M7_Tr0p93D_4Hh_CRyp705ysT3m}`
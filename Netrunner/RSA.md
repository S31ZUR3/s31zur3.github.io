#Cryptography 
## Parameters
- **N**: `21723255931072429115848980770459536154030172827733917513990329373637623433527275863992119031188226322396846874678739489837951572669791608332319205575194978`
- **e**: `65537`
- **Ciphertext**: `3441006844764087090375184770313504091277227629560409440377890666353097157751999814662814854541013552582049280579299116911022716997240115936973499104421709`

## Vulnerability Analysis
In a secure RSA implementation, $N$ should be the product of two large prime numbers ($p$ and $q$). However, observing the value of $N$:
`217232559310...94978`
The last digit is `8`, which means $N$ is even. Therefore, one of the factors is $p = 2$.

## Exploitation Steps

1.  **Factorization**:
    Since $N$ is even, we can easily find $p$ and $q$:
    - $p = 2$
    - $q = N / 2$

2.  **Calculate Euler's Totient ($\phi$)**:
    $\phi(N) = (p - 1) \times (q - 1)$
    Since $p = 2$, this simplifies to $\phi(N) = 1 \times (q - 1) = q - 1$.

3.  **Calculate Private Exponent ($d$)**:
    $d \equiv e^{-1} \pmod{\phi(N)}$

4.  **Decryption**:
    $m \equiv c^d \pmod N$
    The message $m$ is then converted from an integer back to bytes to reveal the flag.

## Solution Script
```python
from Crypto.Util.number import long_to_bytes, inverse

N = 21723255931072429115848980770459536154030172827733917513990329373637623433527275863992119031188226322396846874678739489837951572669791608332319205575194978
e = 65537
c = 3441006844764087090375184770313504091277227629560409440377890666353097157751999814662814854541013552582049280579299116911022716997240115936973499104421709

p = 2
q = N // p

phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, N)

print(long_to_bytes(m).decode())
```

## Flag
**`CTF{rs4_f4ct0r1z4t10n_1s_fun}`**

crypto
## Challenge Analysis
We are provided with a generation script `gen.py` that implements a curve based on a hidden parameter `a`.
The parameter `a` is a fraction `n/d` where `n` and `d` are generated as random 2048-bit primes.
The script calculates points `(x, y)` using the formula:
y = a^3 / (x^2 + a^2)

This is the standard equation for the **Witch of Agnesi** curve.

## Derivation
Let's substitute `a = n/d` into the equation:

y = (n/d)^3 / (x^2 + (n/d)^2)
  = (n^3 / d^3) / (x^2 + n^2 / d^2)

Multiply numerator and denominator by `d^2` to simplify the lower fraction:
y = (n^3 / d^3) / ((x^2 * d^2 + n^2) / d^2)
  = (n^3 * d^2) / (d^3 * (x^2 * d^2 + n^2))
  = n^3 / (d * (x^2 * d^2 + n^2))
  = n^3 / (x^2 * d^3 + n^2 * d)

So we have the point `y` represented as a fraction:
Numerator: `n^3`
Denominator: `x^2 * d^3 + n^2 * d`

Since `n`, `d`, and `x` are distinct large primes, `gcd(n^3, x^2 * d^3 + n^2 * d) == 1` is almost guaranteed. This means the fraction given in `points.txt` is already in its simplest form (irreducible).

## Solution Strategy
1. **Recover `n`**:
   From `points.txt`, take the numerator of `y`.
   n = cubic_root(y_numerator)

2. **Recover `d`**:
   From `points.txt`, take the denominator of `y` (let's call it `Y_den`).
   We know: `Y_den = x^2 * d^3 + n^2 * d`
   Rearranging this gives us a cubic equation for `d`:
   `x^2 * d^3 + n^2 * d - Y_den = 0`

   Since `f(d) = x^2 * d^3 + n^2 * d - Y_den` is strictly increasing for `d > 0`, we can easily find the unique positive integer root `d` using binary search.

3. **Decrypt**:
   Reconstruct the key string `a = "n/d"`.
   The key is `sha256(a).digest()`.
   XOR the ciphertext from `ciphertext.hex` with this key (repeating) to reveal the flag.

## Flag
`nullctf{I_w0nder_wh0_!s_th3_w!tch_0f_Agn3s!?_6920686f7065207468652063746620776173206e696365}`
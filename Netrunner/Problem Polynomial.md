#Cryptography 
## Technical Analysis
- **Number of points ($n$):** 1,658,638
- **Prime Modulus ($MOD$):** 7,514,777,789
- **Observation:** The $x$-coordinates in `encrypted.txt` are sequential integers: $1, 2, 3, \dots, n$.

### The Efficiency Problem
Standard Lagrange interpolation or solving the Vandermonde system is too slow. However, when $x$-coordinates are sequential or follow a specific pattern, we can use Fast Fourier Transform (FFT) based methods or Divide and Conquer to reduce the complexity to $O(n \log^2 n)$.

### The Optimization "Trick"
The Lagrange form of the interpolating polynomial is:
$$P(x) = \sum_{i=1}^n y_i L_i(x)$$
where
$$L_i(x) = \prod_{j \neq i} \frac{x - x_j}{x_i - x_j}$$

Let $M(x) = \prod_{j=1}^n (x - j)$. Then $L_i(x)$ can be written as:
$$L_i(x) = \frac{M(x)}{(x - i) M'(i)}$$

For sequential $x_i = i$, the denominator $M'(i)$ simplifies significantly:
$$M'(i) = \prod_{j=1, j \neq i}^n (i - j) = (i-1)! \cdot (-1)^{n-i} (n-i)!$$

The polynomial $P(x)$ then becomes:
$$P(x) = M(x) \sum_{i=1}^n \frac{v_i}{x - i}, \quad \text{where } v_i = \frac{y_i}{M'(i)}$$

We can compute the sum of rational functions $\sum \frac{v_i}{x - i}$ using a **Divide and Conquer** approach. By recursively combining terms:
$$\frac{P_L}{M_L} + \frac{P_R}{M_R} = \frac{P_L M_R + P_R M_L}{M_L M_R}$$
we can find the numerator of the total sum in $O(n \log^2 n)$ time using fast polynomial multiplication.

## Solution Implementation
I used **SageMath** to handle the finite field arithmetic and fast polynomial multiplication.

1.  **Precompute Factorials:** Calculated factorials up to $n$ to quickly find $M'(i)$.
2.  **Compute $v_i$:** Computed the weights $v_i$ for each point.
3.  **Divide and Conquer:** Implemented an iterative divide-and-conquer algorithm to sum the terms $\frac{v_i}{x - i}$. This avoided recursion depth limits and efficiently utilized Sage's underlying FLINT/NTL libraries for $O(n \log n)$ polynomial multiplication.
4.  **Extract Coefficients:** The resulting numerator polynomial's coefficients directly corresponded to the bytes of the BMP image.

The interpolation took approximately **17 seconds** on the provided environment.

## Flag Recovery
The recovered `output.bmp` was a valid bitmap image. Viewing the image (or converting it to ASCII for CLI verification) revealed the flag.

**Flag:** `CTF{m4th_is_fun_when_y0u_kn0w_the_tr1ck}`

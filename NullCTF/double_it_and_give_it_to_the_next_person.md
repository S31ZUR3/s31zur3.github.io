crypto
### Challenge Overview

The challenge provides a source script `chal.sage` and an output file `output.txt`. The script implements a cryptographic scheme using the NIST P-256 elliptic curve. It generates two secret scalars, `key1` and `key2`, and then runs two iterations of a process where it:

1. Generates a random point P.
    
2. Computes Q=2P (point doubling).
    

- Obfuscates the x-coordinates of P and Q using linear equations involving the secret keys and random coefficients.
    

The goal is to recover `key1` and `key2` to construct the flag: `nullctf{key1 ^ key2}`.

### Analysis

#### 1. The Source Code

The script uses the standard NIST P-256 curve where a=−3. For each iteration, the output gives us:

- P.x=a⋅key1+b
    
- Q.x=c⋅key2+d
    

We are given two sets of these equations (from two iterations). Let's denote the known coefficients for iteration i as Ai​,Bi​,Ci​,Di​. Thus:

xPi​​=Ai​⋅k1​+Bi​

xQi​​=Ci​⋅k2​+Di​

#### 2. The Vulnerability: Point Doubling

The core weakness lies in the mathematical relationship between P and Q. Since Q=2P, the x-coordinate of Q is determined solely by the x-coordinate of P (and the curve parameters).

The formula for point doubling on a curve y2=x3+ax+b provides the x-coordinate of Q:

xQ​=(2yP​3xP2​+a​)2−2xP​

We can eliminate the yP​ term by substituting the curve equation yP2​=xP3​+axP​+b:

xQ​=4(xP3​+axP​+b)(3xP2​+a)2​−2xP​

This rational function relates xQ​ entirely to xP​.

### Solution Strategy

1. **Express k2​ in terms of k1​:** Substitute the linear equations into the doubling formula. Since xP​ depends only on k1​ and xQ​ depends only on k2​, we can rearrange the doubling formula to isolate k2​.
    
    Ci​⋅k2​+Di​=DoublingFormula(Ai​⋅k1​+Bi​)
    
    k2​=Ci​DoublingFormula(Ai​⋅k1​+Bi​)−Di​​
    
2. **Equate and Solve:** Since k1​ and k2​ are constant across iterations, the value of k2​ derived from iteration 0 must equal the value derived from iteration 1.
    
    k2​(from iter 0)=k2​(from iter 1)
    
    This creates a polynomial equation with a single unknown, k1​.
    
3. **Root Finding:** The resulting polynomial is of degree 7 (due to the cubic terms in the curve equation squared). We can solve for the roots of this polynomial over the finite field GF(p) to find k1​.
    

### Solution Script

The following SageMath script implements the algebra described above.

**Note:** If running on a system without SageMath (like a minimal Fedora install), this can be run via Docker/Podman using the `sagemath/sagemath` image.

Python

```python
from sage.all import *

# P-256 Curve Parameters
p = 2**256 - 2**224 + 2**192 + 2**96 - 1
a_curve = -3
b_curve = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

# Data parsed from output.txt
# Iteration 0
A0 = 101391067652419278504279072061964396163420598174591672104811496061093042423713
B0 = 110183945624921546387413554986656742713737778649772602611818367446708850272293
C0 = 43935985468030112938420167350551592897480789520688041577831275174910738854569
D0 = 13245902077735905939963311540878792271896625592735457462639747889134751588655

# Iteration 1
A1 = 113113920295449343615508981422751944711310245958533784150505930220126533492423
B1 = 3292039546575820821367398987680176504505470559384412397685623175088154966631
C1 = 90189751456536603500768763858048652235807590023038279530146107092251468907921
D1 = 93980984745553841375952018332854663310402153214300203815947697055365029221289

# 1. Setup Ring
F = GF(p)
R = PolynomialRing(F, 'x')
x = R.gen() # x represents the unknown key1

data = [(A0, B0, C0, D0), (A1, B1, C1, D1)]
numerators = []
denominators = []

print("[*] Constructing polynomials...")
for A, B, C, D in data:
    # xP expressed in terms of key1 (x)
    xP = A * x + B
    
    # Calculate yP^2 from curve equation
    yP_sq = xP**3 + a_curve * xP + b_curve
    
    # Doubling formula relation: 
    # xQ = ((3xP^2 + a)^2) / (4yP^2) - 2xP
    # Substituting xQ = C*k2 + D and rearranging for k2:
    # k2 = [ (3xP^2 + a)^2 - (8xP + 4D)*yP^2 ] / [ 4*C*yP^2 ]
    
    term_num = (3*xP**2 + a_curve)**2 - (8*xP + 4*D) * yP_sq
    term_den = 4 * C * yP_sq
    
    numerators.append(term_num)
    denominators.append(term_den)

# 2. Equate the two expressions for k2
# num0 / den0 = num1 / den1  =>  num0 * den1 - num1 * den0 = 0
final_poly = numerators[0] * denominators[1] - numerators[1] * denominators[0]

print("[*] Finding roots (candidates for key1)...")
roots = final_poly.roots()

for r, multiplicity in roots:
    try:
        k1_candidate = r
        
        # Recover key2 using the first iteration
        num = numerators[0](k1_candidate)
        den = denominators[0](k1_candidate)
        
        if den == 0: continue
        k2_candidate = num / den
        
        # Calculate Flag
        val_k1 = int(k1_candidate)
        val_k2 = int(k2_candidate)
        flag_val = val_k1 ^ val_k2
        
        print(f"Flag: nullctf{{{flag_val:064x}}}")
        break
    except Exception as e:
        print(f"Error: {e}")
```

## Flag: nullctf{25b6b8151d54b7f9e5fc3181e1d5b5a97464d019dde57aca90df349a8c951a02}
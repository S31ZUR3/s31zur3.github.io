android
## Challenge Overview

This challenge provides an Android application in which the flag is not stored directly, but instead generated at runtime via obfuscated Java code.

Inside the APK, the critical logic is located in:

`com.heroctf.freeda1.utils.Vault`

The flag is computed by the method:

`get_flag()`

Our goal is to reverse this function and rebuild the flag.

---

## Step 1: Locate the Flag Generator

After decompiling the APK with jadx / JADX-GUI / JADX CLI, we find this class:

```java
final class Vault {
    public static final int[] a = {52, 88, 27, 32, ... 202, 66};

    public static String get_flag() { ... }

    private static int seed() { ... }
}

```

The flag is not stored as a literal string.  
Instead, an encrypted integer array is used and decoded at runtime.

---

## Step 2: Understand the Seed Generation

The `seed()` function creates a decryption key using hardcoded class names.

```java
int iHashCode =
        ("com.heroctf.freeda1.MainActivity".hashCode() ^ (-1056969150))
      ^ "com.heroctf.freeda1.utils.CheckFlag".hashCode();

return iHashCode ^ (Integer.rotateLeft(iHashCode, 7) * (-1640531527));

```

### Summary

The seed is based on:

- Two Java class names
    
- XOR operations
    
- Bit rotation
    
- Large magic constants
    

This prevents simply copying the encrypted data without reproducing the logic.

---

## Step 3: Reconstruct the Shuffle

After generating the seed, an index array is created:

`[0, 1, 2, ..., 38]`

Then it is **shuffled using a XORSHIFT PRNG algorithm**:

```java
int i2 = (-1515870811) ^ iSeed;

for (int i = 38; i >= 0; i--) {
    i2 = xorshift(i2);
    int idx = i2 % (i + 1);
    swap(iArr[i], iArr[idx]);
}

```

This step randomizes the order in which encrypted bytes are accessed.

The algorithm is deterministic:  
→ same seed = same order.

---

## Step 4: Decryption Logic

For each byte:


```java
int val = a[iArr[i]] - i; 
val = ROTATE_RIGHT(val, shift); 
val ^= seed_fragment;
```

Where:

- `shift = (seed >> 27) & 7`
    
- `seed_fragment = seed shifted per byte`
    
- rotation + xor produce decrypted output
    

---

## Step 5: Port Everything to Python

Instead of running the Android app, the logic can be reproduced externally.

We reimplemented:

- Java string hashing
    
- Integer rotation
    
- XORSHIFT PRNG
    
- Byte transformations
    

### Python Solver (Final)

``` python
a = [52,88,27,32,27,186,96,109,45,202,42,125,25,134,159,69,47,142,192,
     184,13,19,139,173,59,129,0,158,165,188,13,62,74,184,58,75,172,202,66]

def jhash(s):
    h = 0
    for c in s:
        h = (31*h + ord(c)) & 0xffffffff
    return h

def rol(x,n):
    return ((x << n) | (x >> (32-n))) & 0xffffffff

C1 = (-1056969150) & 0xffffffff
C2 = (-1515870811) & 0xffffffff
C3 = (-1640531527) & 0xffffffff

hc = (jhash("com.heroctf.freeda1.MainActivity") ^ C1) ^ jhash("com.heroctf.freeda1.utils.CheckFlag")
seed = (hc ^ (rol(hc,7) * C3)) & 0xffffffff

iArr = list(range(39))
i2 = (C2 ^ seed) & 0xffffffff

def xorshift(x):
    x ^= (x << 13) & 0xffffffff
    x ^= (x >> 17)
    x ^= (x << 5) & 0xffffffff
    return x & 0xffffffff

for i in range(38,-1,-1):
    i2 = xorshift(i2)
    idx = i2 % (i+1)
    iArr[i], iArr[idx] = iArr[idx], iArr[i]

out = []
for i in range(39):
    i8 = ((a[iArr[i]] & 255) - i) & 255
    rot = (seed >> 27) & 7
    val = ((i8 << (8-rot)) | (i8 >> rot)) & 255
    val ^= (seed >> ((i & 3)*8)) & 255
    out.append(val)

print(bytes(out).decode("latin1"))

```
---

## Step 6: Final Result

Running the script outputs:

`Hero{1_H0P3_Y0U_D1DN'T_S7A71C_4N4LYZ3D}`

[[HeroCTF 2025]]


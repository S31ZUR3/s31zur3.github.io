#Cryptography 
## Code Analysis

The core logic is in the `scramble` function:

```python
def scramble(L):
  A = L
  i = 2
  while (i < len(A)):
    A[i-2] += A.pop(i-1)
    A[i-1].append(A[:i-2])
    i += 1
    
  return L
```

### How it works:
1. The input `L` is a list of lists, where each inner list contains a single character of the flag in hex format: `[['0x43'], ['0x54'], ['0x46'], ...]`.
2. The loop starts at `i = 2`.
3. `A[i-2] += A.pop(i-1)`: This takes the element at index `i-1`, removes it from the list, and appends its contents (the hex string) to the element at `i-2`. This effectively creates pairs of characters.
4. `A[i-1].append(A[:i-2])`: This takes the new element at `i-1` (which was previously at `i`) and appends a slice of the list before `i-2` into it as a nested list.
5. This process continues, shifting the list and nesting previous "entangled" parts into newer ones.

### The Result:
The output in `enc.txt` is a deeply nested list where the hex strings (the actual flag characters) are stored as string elements within various levels of sublists. Crucially, even though the structure is complex, the hex strings themselves remain un-transformed.

## Solution

Since the cipher only moves the hex strings around without altering their values, we can recover the flag by iterating through the nested structure and extracting every string that looks like a hex value in the order they appear.

### Solving Script:

```python
import ast

# Read the encoded data
with open('enc.txt', 'r') as f:
    data = f.read().strip()

# Safely evaluate the string representation of the list
A = ast.literal_eval(data)

flag = ""
# Recursively or iteratively find all strings in the nested structure
def extract_strings(item):
    res = ""
    if isinstance(item, str):
        return chr(int(item, 16))
    elif isinstance(item, list):
        for subitem in item:
            res += extract_strings(subitem)
    return res

# Since the top level is a list of pairs/groups
for item in A:
    for x in item:
        if isinstance(x, str):
            flag += chr(int(x, 16))

print(f"Flag: {flag}")
```

Running this script extracts the characters in the correct order.

## Flag
`CTF{Quantum_!s_super_entanglement}`

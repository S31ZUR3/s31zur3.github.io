Reverse Engineering
### 1. Initial Analysis & Unpacking

We started with a Windows executable named `effortless.exe`. A quick inspection of the file strings or headers (specifically section names like `UPX0`, `UPX1`) revealed it was packed with **UPX**.

To analyze the code logic, we first unpacked it:

Bash

```
upx -d effortless.exe
```

### 2. Static Analysis

Loading the unpacked binary into Ghidra, we navigated to the `entry` function. Since `strings` didn't reveal the flag directly, we knew the program likely constructed it at runtime.

We followed the call chain from `entry` to `WinMain` (`FUN_140001b34`). The `WinMain` function was straightforward:

1. It performed some anti-debug checks (`IsDebuggerPresent`).
    
2. It decrypted a class name and window title using XOR.
    
3. It created a window using `CreateWindowExA` and entered a message loop.
    

The core logic resided in the **Window Procedure** (`FUN_140001668`), which handles events like mouse clicks.

### 3. Analyzing the Window Procedure

Inside the Window Procedure, we found a handler for `WM_LBUTTONDOWN` (`0x201`) and `WM_RBUTTONDOWN` (`0x204`).

The code was tracking user inputs:

- **Left Click (0x201):** Stored the character `'L'` (0x4C).
    
- **Right Click (0x204):** Stored the character `'R'` (0x52).
    

These characters were saved into a buffer. Once the counter reached **20 clicks**, the program performed two checks:

#### The "Effortless" Bait (The Trap)

The code checked if the **first** and **last** clicks were both `'L'`.

C

```
if ((Buffer[0] == 'L') && (Buffer[19] == 'L')) { ... }
```

If this condition was met, it executed a routine that displayed a MessageBox. However, as discovered during testing, this path was a troll/bait that likely displayed the text **"Enough thinking"** or a fake flag, discouraging further analysis.

#### The Real Solution (The Sequence)

If the "Effortless" check failed (or concurrently), the program compared the entire 20-click buffer against a generated sequence using `memcmp`:

C

```
FUN_140001380(TargetBuffer);
if (memcmp(UserBuffer, TargetBuffer, 20) == 0) {
    // Success path: Decrypt and execute shellcode/flag logic
}
```

### 4. Decrypting the Click Sequence

To find the correct sequence, we analyzed the generation function `FUN_140001380`. It initialized a byte array with 0s and 1s and transformed them:

- **Logic:** `(-(cVar1 != '\0') & 6U) + 0x4C`
    
- **0** becomes `0x4C` ('L')
    
- **1** becomes `0x52` ('R')
    

Reconstructing the array from the code gave us the required sequence:

|Click #|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|**Type**|**L**|**R**|**L**|**L**|**R**|**R**|**L**|**R**|**L**|**R**|**L**|**L**|**R**|**L**|**L**|**R**|**L**|**R**|**L**|**L**|

### 5. Execution

We ran the unpacked executable and performed the clicks exactly as decoded: **Left, Right, Left, Left, Right, Right, Left, Right, Left, Right, Left, Left, Right, Left, Left, Right, Left, Right, Left, Left.**

Upon the 20th click, the application decrypted the memory and revealed the true flag.

**Flag:**

```
nexus{1_5p3n7_h0ur5_0n_7h15_bu7_17_w45_w0r7h_1t_7h4nk5_f0r_pl4y1ng}
```


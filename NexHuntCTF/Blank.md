### **1. Initial Analysis**

We started by inspecting the binary using `strings`, which dumps all printable characters from the file.

- **Result:** The flag was not found in the static text. This indicated that the flag is likely constructed dynamically at runtime or obfuscated to prevent simple static analysis.
    

### **2. Dynamic Analysis (The Solution)**

We proceeded to run the binary with **`strace`** (System Call Tracer). This tool intercepts and records the system calls called by a process and the signals received by that process.

**Command:**

Bash

```
strace ./blank
```

**Observation:** Looking at the `strace` logs, we see a series of unusual `write` system calls targeting file descriptor **5**:

Bash

```
write(5, "nexus{", 6)                   = -1 EBADF (Bad file descriptor)
write(5, "th3_f", 5)                    = -1 EBADF (Bad file descriptor)
write(5, "l4g_w1ll", 8)                 = -1 EBADF (Bad file descriptor)
...
```

**What is happening here?**

- **File Descriptors (FD):** In Linux, FD `0` is Standard Input, `1` is Standard Output (your screen), and `2` is Standard Error.
    
- **The Trick:** The challenge author deliberately wrote code to write the flag to **FD 5**. Since FD 5 was never opened by the program, the system call fails with `EBADF` (Bad File Descriptor) and nothing prints to the screen.
    
- **The Leak:** Even though the `write` failed, `strace` captures the **arguments** passed to the system call _before_ execution. This reveals the data the program _tried_ to write.
    

### **3. Flag Reconstruction**

We can simply concatenate the strings from the `write` arguments in the order they appear:

1. `nexus{`
    
2. `th3_f`
    
3. `l4g_w1ll`
    
4. `_r3ve4l`
    
5. `_1ts3l`
    
6. `f_wh3n`
    
7. `_y0u_`
    
8. `st0p_`
    
9. `look`
    
10. `1ng}`
    

### **Final Flag**

Plaintext

```
nexus{th3_fl4g_w1ll_r3ve4l_1ts3lf_wh3n_y0u_st0p_look1ng}
```
pwn
## 1. Vulnerability Analysis

By analyzing the binary with GDB, we discovered two critical flaws:

1. **Dangling Pointer (UAF):** When selecting **Option 2 (Throw away fruit)**, the program frees the memory chunk but fails to clear the pointer in the `fruit_basket` array. This allows us to access and edit "freed" memory.
    
2. **Heap Reuse:** The **Option 6 (Reset leaderboard)** function allocates a new memory chunk of size `0x24` (padded to `0x30`). This is the exact same size as a "Fruit" chunk. Because the heap manager (glibc allocator) prioritizes recycling recently freed chunks (via the `tcache`), resetting the leaderboard will reuse the memory address of the most recently freed fruit.
    

**The Win Condition:** The function `perform_special_action` (Option 5) checks if the data inside the `leaderboard` matches the string **"Admin"**.

## 2. The Exploit Strategy

We can trick the program into making the `leaderboard` and our `fruit_basket` point to the **same memory address**. This allows us to use the "Edit Fruit" feature to overwrite the `leaderboard` data with "Admin".

## 3. Manual Execution Steps

Here is the exact sequence of inputs to solve the challenge manually (works on both local binary and remote server).

### Step 1: Slice a Fruit (Allocation)

We create a fruit to reserve a chunk of memory on the heap.

- **Menu Choice:** `1`
    
- **Fruit Name:** `Trash` (Any name works here)
    
- **Points:** `1`
    

### Step 2: Throw Away Fruit (Free)

We free the fruit we just created. The memory is released to the "recycle bin," but our pointer to it (Index 0) remains active (dangling).

- **Menu Choice:** `2`
    
- **Index:** `0`
    

### Step 3: Reset Leaderboard (Aliasing)

We choose to reset the leaderboard. The program requests memory. The allocator notices the chunk we just freed in Step 2 fits perfectly, so it gives that specific memory address to the `leaderboard`.

- **Crucial State:** `fruit_basket[0]` and `leaderboard` now point to the **same address**.
    
- **Menu Choice:** `6`
    

### Step 4: Overwrite Data

We use the "Edit" feature on the dangling fruit pointer. Since it points to the same place as the leaderboard, we are actually editing the leaderboard.

- **Menu Choice:** `4`
    
- **Index:** `0`
    
- **New Name:** `Admin`
    
    - _Note: This must be exact. Case-sensitive._
        

### Step 5: Trigger Victory

Now that the leaderboard contains the string "Admin", we run the check.

- **Menu Choice:** `5`
    

**Output:**

Plaintext

```
Admin Welcome!
Flag: VuwCTF{fr33_th3_h34p_sl1c3_th3_fr00t}
```

## Summary

This challenge is a textbook example of **Heap Aliasing**. By understanding that `malloc` recycles memory and that the program didn't clean up its pointers (`fruit_basket[0]`), we were able to control an internal program structure (`leaderboard`) using user-accessible controls (`edit_fruit`).
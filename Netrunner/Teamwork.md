#Misc 

### 1. Extracting the Files
The challenge provided a `ch20.zip` file. After unzipping, I discovered a directory named `ch20/drop-in` containing a `.git` repository and a `flag.py` script.

### 2. Initial Investigation
I first read the `flag.py` file in the current branch:
```python
print("Printing the flag...")
print("CTF{t3@mw0rk_", end='')
```
This only gave me the first part of the flag: `CTF{t3@mw0rk_`.

### 3. Exploring Git History
Since the prompt mentioned a "team" working on "new features," I checked for other branches in the repository:
- `main`
- `feature/part-1`
- `feature/part-2`
- `feature/part-3`

I used `git log --all -p` to view the commit history and the specific changes (diffs) made in every branch.

### 4. Extracting Flag Parts
From the logs, I identified the following parts:

*   **Branch `feature/part-1`**: Added `CTF{t3@mw0rk_`
*   **Branch `feature/part-2`**: Added `m@k3s_th3_dr3@m_`
*   **Branch `feature/part-3`**: Added `w0rk_4c24302f}`

## Conclusion
By combining the strings found in the separate feature branches, the full flag was reconstructed.

**Flag:** `CTF{t3@mw0rk_m@k3s_th3_dr3@m_w0rk_4c24302f}`

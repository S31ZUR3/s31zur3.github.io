#Misc 
### 1. Initial Exploration
I started by unzipping the `drop-in.zip` file, which revealed a directory named `drop-in` containing a `.git` folder and a `message.txt` file.

### 2. Investigating Git History
Running `git log` showed a series of commits with messages like "A change", "Another change", "Final change", etc. This suggested that the flag might have been modified or replaced over time.

### 3. Deep Dive into Commit Diffs
I used `git log -p message.txt` to examine the actual changes made to the `message.txt` file in each commit. This allowed me to see the strings that were added and removed.

### 4. Identifying the Flag
In the commit history, I observed multiple variations of the flag format `CTF{...}`. Specifically, in commit `0eafbe73766f55ae004d2bee564627a655694454` (titled "Final change 2"), the following change was made:

```diff
-CTF{s@n1t1z3_be3dd3da_akerths}
+CTF{s@n1t1z3_be3dd3da_akergjkn}
```

This confirmed that `CTF{s@n1t1z3_be3dd3da_akergjkn}` was one of the states of the flag before being changed again in subsequent commits.

## Final Flag
The flag is: **CTF{s@n1t1z3_be3dd3da_akergjkn}**

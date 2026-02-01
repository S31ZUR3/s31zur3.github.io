#Web 
### 1. Initial Inspection & Recovery
Upon listing the files, we saw a `.git` directory. Checking `git status` and `git log` revealed that the repository was corrupt (missing objects).

```bash
git status
# fatal: bad object HEAD
```

However, the `git log` did show the remote repository URL: `https://github.com/MITS-Cyber-Security-Club/eschaton-web-nowyouseeme.git`.

We restored the repository by fetching from this origin:

```bash
git fetch origin
git checkout master
```

### 2. Exploring Commit History
With the repository restored, we examined the commit history:

```bash
git log --all --graph --oneline
```

Output:
```
* 69259f3 fix: exposed config
* c7beba9 feat: Add custom Nginx configuration...
* 6bc313d I hope they wont see this
* d9b9f22 Working version ig
```

We checked the files in the current `master` branch.
- `flag.txt` contained: `esch{re411y_?_bruhhhh....}` (Decoy)
- `secret/flag.txt` contained: `esch{f4ke_fl4g_123_h3h3}` (Decoy)
- `robots.txt` contained: `esch{not_that_easy_bro}` (Decoy)

### 3. Analyzing "Working version ig"
The commit `d9b9f22` ("Working version ig") introduced `index.js`, which was deleted in later commits. We inspected this file.

```bash
git show d9b9f22:index.js
```

The file `index.js` contained typical JavaScript for an "eyeball tracking" effect, but at the very end, there was a suspicious obfuscated block using a `Proxy` and `eval`:

```javascript
new Proxy(
  {},
  {
    get: (_, n) =>
      eval(
        [...n].map((n) => +("ﾠ" > n)).join``.replace(/.{8}/g, (n) =>
          String.fromCharCode(+("0b" + n)),
        ),
      ),
  },
)
  .ﾠﾠㅤﾠﾠﾠﾠﾠﾠﾠㅤﾠﾠﾠﾠﾠﾠﾠ... (long string of invisible characters)
```

### 4. Decoding the Payload
The obfuscation logic relied on two specific invisible characters:
- `ﾠ` (U+FFA0: HALFWIDTH HANGUL FILLER)
- `ㅤ` (U+3164: HANGUL FILLER)

The code converts these characters into binary (0s and 1s) and then to ASCII characters.

We wrote a decoding script to process the hidden string:

```javascript
// Logic extracted from the source:
// [...n].map((n) => +("ﾠ" > n)).join``.replace(/.{8}/g, (byte) => String.fromCharCode(parseInt(byte, 2)))
```

Running the decoder on the hidden string revealed the following code:

```javascript
   const messageDiv = document.createElement("div");
    messageDiv.id = "message";
    // ... styling code ...
    messageDiv.textContent = "Do you see me?";
    // esch{y0u_s33_,_but_u_d0_n0t_0bs3rv3}
    // Said Sherlock Holmes.
```

### 5. Conclusion
The flag was hidden in the comments of the decoded JavaScript payload.

**Flag:** `esch{y0u_s33_,_but_u_d0_n0t_0bs3rv3}`
forensics
### 1. Reconnaissance

We were provided with an encrypted archive, `BurgerKing.zip`, and a partial file, `partial.svg`. The challenge description hinted at a "forensics team" called "Burger King Crackers," a reference to the **bkcrack** (Biham-Kocher Crack) tool used for exploiting legacy Zip encryption.

First, we analyzed the archive to check the encryption and compression methods:

Bash

```
unzip -v BurgerKing.zip
```

**Findings:**

- **Encryption:** Legacy ZipCrypto (implied by the vulnerability context).
    
- **Compression:** `Stored` (0% compression).
    
- **Files:** 5 SVG files (`Hole.svg`, `LockAndKey.svg`, `Space.svg`, `Webs.svg`, `SVGsSuck.svg`).
    

The fact that the files were **Stored** meant the raw plaintext bytes would match the encrypted bytes exactly, making a **Known Plaintext Attack (KPA)** trivial.

### 2. Plaintext Preparation

We examined the provided `partial.svg` file:

Bash

```
cat partial.svg
# Output: <svg xmlns="http://www.w3.org/2000/svg"
```

This string corresponds to the standard XML header found at the beginning of almost all SVG files. Since we know the start of the plaintext for the encrypted files, we can derive the internal encryption keys.

We ensured the plaintext file was clean (no extra newlines) for the attack:

Bash

```
printf '<svg xmlns="http://www.w3.org/2000/svg"' > partial.svg
```

### 3. Cracking the Keys

We used `bkcrack` to perform the Known Plaintext Attack. We targeted `Space.svg` (though any of the SVGs would likely work) using the clean plaintext file.

Bash

```
./bkcrack -C BurgerKing.zip -c Space.svg -p partial.svg
```

The attack succeeded quickly because there was no compression to guess. **Recovered Keys:** `b9540c69 069a11f9 fd31648f`

### 4. Decryption and Extraction

With the internal keys recovered, the password was no longer needed. We generated a new, unlocked version of the archive with a known password (`easy`) to extract all files at once.

Bash

```
./bkcrack -C BurgerKing.zip -k b9540c69 069a11f9 fd31648f -U unlocked.zip easy
unzip unlocked.zip
```

### 5. Retrieving the Flag

After extracting the files, we examined `SVGsSuck.svg` (the largest file in the archive). Opening the image revealed the flag written clearly within the graphic.

**Flag:**

Plaintext

```
CACI{Y0U_F0UND_M3!}
```
[[PatriotCTF-2025]]
rev
## 1. Initial Analysis
The challenge provided a file named `vaultchain.zip`. Initial inspection using `zipinfo` and `zipdetails` revealed:
- It contained a single file: `vaultchain.exe`.
- It was encrypted using AES-256 (Compression Method 99), which is not supported by standard Linux `unzip`.
- There was a slight header anomaly (extra bytes at the start), which was fixed to ensure compatibility with cracking tools.

## 2. Cracking the Zip Password
Since the zip was password-protected, I used `zip2john` to extract the hash and `john` (John the Ripper) with the `rockyou.txt` wordlist to crack it.
- **Command:** `zip2john vaultchain.zip > vault.hash && john --wordlist=/usr/share/wordlists/rockyou.txt vault.hash`
- **Password Found:** `champers1`

## 3. Extracting the Executable
Using the `pyzipper` Python library (which supports AES-encrypted zips), I extracted `vaultchain.exe`.

## 4. Reverse Engineering the Binary
Analysis of the strings in `vaultchain.exe` indicated it was a **PyInstaller** bundle (strings like `pyi-python-flag` and `python310.dll` were present).
- I used `pyinstxtractor.py` to extract the contents of the executable.
- The extraction yielded several files, including `chall.pyc`, which contained the main logic of the application.

## 5. Recovering the Flag
Instead of full decompilation, I inspected the strings within `chall.pyc`. I found:
- A hex-encoded byte sequence: `20 01 19 29 1e 2f 00 00 1d 0e 1f 1c 0a 19 0a 01 2c 3a 17 1f 13 13 00 0b 2c 19 19 1d 11 13 00 00 14 06 17 1c 0a 19 0a 01 0e`
- A specific mention of a **FLAG XOR KEY**: `sixseven`.

By XORing the byte sequence with the repeating key `sixseven`, the flag was revealed.

## 6. Flag
**ShaZ{Yennggooooo_Solveee_panteengooooooo}**
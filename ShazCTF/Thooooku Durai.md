forensics

I started by verifying the file integrity using pngcheck. The tool immediately flagged that the file was not recognized as a valid image.
Bash

```bash
	$ pngcheck -v thala_chal.png
	File: thala_chal.png
	this is neither a PNG or JNG image nor a MNG stream
```

This indicated that the Magic Bytes (File Signature) were corrupted.
2. Fixing the Magic Bytes

A standard PNG file must start with the following 8 bytes: 89 50 4E 47 0D 0A 1A 0A. I used dd to patch the header without altering the rest of the file data.

```bash
printf "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A" | dd of=thala_chal.png bs=1 count=8 conv=notrunc
```

3. Fixing the IHDR Chunk

After fixing the signature, I ran pngcheck again. It recognized the file type but failed on the first chunk:
```bash
$ pngcheck -v thala_chal.png
  invalid chunk name "C#gB" (43 23 67 42)
  ```

I examined the hex dump around the error:

```bash
$ hexdump -C thala_chal.png | grep -C 2 "C#gB"
00000000  89 50 4e 47 0d 0a 1a 0a  55 64 54 53 43 23 67 42

The data at offset 0x08 corresponds to the first chunk, which must be the IHDR chunk.

    Corrupted Length: 55 64 54 53 (Garbage) → Should be 00 00 00 0D (13 bytes).

    Corrupted Type: 43 23 67 42 (C#gB) → Should be 49 48 44 52 (IHDR).
```
I patched these 8 bytes using dd:

```bash
printf "\x00\x00\x00\x0D\x49\x48\x44\x52" | dd of=thala_chal.png bs=1 seek=8 count=8 conv=notrunc
```
4. Result

After fixing the header and the IHDR definition, the image was valid. Opening the image revealed the flag.

Flag:
`ShaZ{ad111ch11_7h0Okum_7h000ku_dur411}`
forensics
### 1. Decoding doramon.txt
The file `doramon.txt` appeared to be a program in the *Whitespace* language, but it was actually a binary stream encoded with spaces and tabs.
- **Space** represented `0`
- **Tab** represented `1`

I wrote a script to parse these chunks, convert them to bytes, and save the output.

```python
# Decoder script logic
with open('doramon.txt', 'r') as f:
    content = f.read()

chunks = content.split(' ')
bytes_list = []

for chunk in chunks:
    # Clean up newlines if present
    if chunk.startswith('\n\n'):
        chunk = chunk[2:]

    # Map characters to bits
    bits = chunk.replace('\t', '1').replace('\n', '0')
    if bits:
        try:
            bytes_list.append(int(bits, 2))
        except:
            pass

with open('doramon.mp4', 'wb') as out:
    out.write(bytes(bytes_list))
```

**Result:** A valid video file `doramon.mp4`.

### 2. File Analysis & Extraction
I analyzed `doramon.mp4` using `binwalk` to check for embedded artifacts.

```bash
binwalk -e doramon.mp4
```

**Output:**
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
143793        0x231B1         JPEG image, total size: 208824 bytes
```

I extracted the JPEG image (automatically extracted as `extracted.jpg` or found in the `_doramon.mp4.extracted` folder).

### 3. Steganography Extraction
With the extracted image `extracted.jpg` and the key `doracake` from the challenge description, we used `steghide` to extract hidden data.

```bash
steghide extract -sf extracted.jpg -p "doracake"
```

**Output:**
```
wrote extracted data to "flag.txt".
```

### 4. The Flag
Reading `flag.txt` revealed the flag:

```
ShaZ{d0r43m0n_uh_r3m4nd_j4!L_u114_v4ch!t4444ng000}
```

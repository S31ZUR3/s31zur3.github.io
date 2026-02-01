#Rev 
## 1. Initial Reconnaissance
We began by analyzing the provided file `textmorph`.
- **Command**: `file textmorph`
- **Result**: Identified as a 64-bit ELF executable (Linux binary).
- **Behavior**: Running `./textmorph --help` displayed standard text processing options (encode, decode, hash, etc.), implying a functional tool.

## 2. Strings Analysis
We used the `strings` utility to look for human-readable text inside the binary.
- **Command**: `strings textmorph`
- **Findings**:
    - **Decoys**: Found strings like `CTF{tr0lled_by_v3rsi0n_str1ng}` and `CTF{c0nfig_1s_n0t_th3_w4y}`, which were clearly fake flags.
    - **Architecture**: Strings like `PyRun_SimpleString`, `_MEIPASS`, and `pyi-python-flag` strongly suggested the binary was created with **PyInstaller**.
    - **The Artifact**: We located an unusually large, continuous string starting with `eNrc...`.

## 3. Identifying the Suspicious Blob
The prefix `eN` is a tell-tale sign of **Zlib-compressed data** that has been encoded in **Base64**.
- **Signature**: `eN...` often corresponds to the zlib header `0x78 0x9C` (default compression) when base64 encoded.
- **Hypothesis**: This blob contained a hidden file or resource relevant to the challenge.

## 4. The Extraction Process
We wrote a Python script to surgically extract, decode, and decompress this data block.

### Extraction Script (`extract_gif.py`)
```python
import zlib
import base64

# Open the binary in binary read mode
with open('textmorph', 'rb') as f:
    data = f.read()

# The specific signature identified from the 'strings' output
start_pattern = b'eNrc22VTW23DtmHcobh7cXd3d3crTpDgbsXd3Yu7uxcnuLu7U6BI4WrJm2fuf/HmayYzmXMd257MykReUU5A0III+gn6TQWKAAOdEucLNjk98VcmTipKGQ4K'

try:
    # 1. Locate the start of the Base64 string
    start_idx = data.index(start_pattern)
    end_idx = start_idx

    # 2. Find the end of the string by scanning for non-Base64 characters
    # Valid Base64: A-Z, a-z, 0-9, +, /, =
    while end_idx < len(data):
        c = data[end_idx]
        if not (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c == 43 or c == 47 or c == 61):
            break
        end_idx += 1

    b64_data = data[start_idx:end_idx]
    print(f"Found valid Base64 block of size: {len(b64_data)} bytes")

    # 3. Decode Base64 -> Compressed Data
    compressed = base64.b64decode(b64_data)

    # 4. Decompress Zlib -> Raw Data
    decompressed = zlib.decompress(compressed)

    # 5. Verify and Save
    # Check for GIF magic bytes (GIF89a)
    if decompressed.startswith(b'GIF89a'):
        print("Header detected: GIF89a. Saving file...")
        with open('extracted.gif', 'wb') as out:
            out.write(decompressed)
        print("Successfully extracted 'extracted.gif'")
    else:
        print("Decompressed data is not a GIF.")
        # Optional: Save unknown data for inspection
        with open('unknown_output.bin', 'wb') as out:
            out.write(decompressed)

except ValueError:
    print("Start pattern not found in binary.")
except Exception as e:
    print(f"Extraction failed: {e}")
```

## 5. Verification
After running the script, we verified the output.
- **Command**: `file extracted.gif`
- **Output**: `extracted.gif: GIF image data, version 89a, 281 x 498`
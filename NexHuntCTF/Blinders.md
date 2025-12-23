Miscellaneous
## 🕵️ Analysis & Solution

### 1. Initial Reconnaissance (`binwalk`)

The first step was to analyze the file structure to check for any embedded files or corrupted headers using `binwalk`.

**Command:**

Bash

```
binwalk output.png
```

**Output:**

Plaintext

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1280 x 853, 8-bit/color RGBA, non-interlaced
41            0x29            Zlib compressed data, default compression
```

_Observation:_ The file appears to be a valid PNG image. `binwalk` didn't immediately detect any appended files (like ZIPs or JPEGs) grafted onto the end, suggesting the data was hidden inside the image bits itself (LSB steganography) or within specific data chunks.

### 2. Deep Steganography Analysis (`zsteg`)

Since it was a PNG, we used `zsteg`, a tool designed to detect hidden data in PNG/BMP files by iterating through different Least Significant Bit (LSB) combinations and pixel orders. We used the `-a` flag to try all known methods.

**Command:**

Bash

```
zsteg -a output.png
```

**Output:** The tool successfully extracted the hidden string from the pixel data:

Flag: `nexus{yea_u_didi_v2er_wekcj7}`

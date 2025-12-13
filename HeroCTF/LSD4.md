Misc
### 1. Analysis

The file provided is named `secret.jpg`. However, running the `file` command or checking the headers reveals it is actually a **PNG image**. This is crucial because PNG is a lossless format, meaning pixel values (and their Least Significant Bits) are preserved, unlike in JPEG.

The description explicitly mentions a specific Region of Interest (ROI):

- **Start:** (1000, 1000)
    
- **Size:** 100x100 pixels
    

The Title "LSD" is a reference to **Least Significant Digit** (or Bit) steganography. Since automated tools like `zsteg` analyze the whole image (which is full of psychedelic noise), they fail. We must write a script to target the specific ROI.

### 2. Methodology

1. **Crop the Image:** Isolate the 100x100 square at (1000, 1000).
    
2. **LSB Extraction:** Extract the Least Significant Bit (Bit 0) from the pixels in this region.
    
3. **Channel Isolation:** Initially, reading bits from all channels (RGB) returned garbage data. By iterating through channels individually (Red, Green, Blue, Alpha), we discovered the message was hidden exclusively in the **Red Channel**.
    

### 3. Solver Script

Here is the Python script used to solve the challenge:

Python

```
from PIL import Image

def solve():
    # Load the image (PIL handles the fake .jpg extension automatically)
    img = Image.open("secret.jpg").convert("RGBA")
    
    # Crop the Region of Interest specified in the description
    # Box = (left, upper, right, lower)
    roi = img.crop((1000, 1000, 1100, 1100))
    pixels = list(roi.getdata())
    
    print("[+] Extracting LSB from Red Channel...")

    # Extract LSB from the Red Channel only (Index 0)
    bits = [pixel[0] & 1 for pixel in pixels]

    # Convert bits to characters
    chars = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) == 8:
            # Join bits and convert to int, then to char
            byte_val = int("".join(map(str, byte_bits)), 2)
            chars.append(chr(byte_val))

    full_message = "".join(chars)
    
    # Locate and print the flag
    if "Hero{" in full_message:
        start = full_message.find("Hero{")
        end = full_message.find("}", start) + 1
        print(f"\n🚩 FLAG: {full_message[start:end]}")
    else:
        print("Flag pattern not found in Red channel. Check output:\n")
        print(full_message[:100])

if __name__ == "__main__":
    solve()
```

### 4. Output & Flag

Running the script produces a long string of text regarding the definition of Steganography, with the flag embedded inside.

**Output:**

Plaintext

```
Steganography is the practice of concealing information... Hero{M4YB3_TH3_L4ST_LSB?} ...
```

**Flag:**

```
Hero{M4YB3_TH3_L4ST_LSB?}
```

[[HeroCTF 2025]]


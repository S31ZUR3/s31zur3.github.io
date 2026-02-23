#Cryptography 
## Objective
The goal was to recover an encrypted image from a series of three images (`left.bmp`, `middle.bin`, and `right.bmp`) and find the hidden flag.

## Discovery
1.  **Extracting Files:** Unzipping `images.zip` revealed:
    - `left.bmp`: A valid BMP image.
    - `middle.bin`: An encrypted binary file.
    - `right.bmp`: A valid BMP image.
2.  **Initial Analysis:** 
    - `left.bmp` and `right.bmp` are identical in size and header structure.
    - `middle.bin` is slightly larger, suggesting a possible header or offset for the encrypted data.
    - Given the hint "block-cipher" and "two images before they were encrypted", it was likely that one of the unencrypted images (or both) served as a key for an XOR-based encryption.

## Strategy
The hypothesis was that `middle.bin` contained the pixel data of the middle part of the original image, XORed with the pixel data of `left.bmp`.

### Steps:
1.  **Analyze BMP Structure:** BMP files have a header (usually 138 bytes for these specific files).
2.  **Determine Offset:** The encrypted data in `middle.bin` was found to start at an offset of 160 bytes.
3.  **XOR Decryption:**
    - Read the pixel data from `left.bmp`.
    - Read the encrypted data from `middle.bin`.
    - XOR the two streams.
    - Reconstruct a valid BMP file (`middle_decrypted.bmp`) by combining the header from `left.bmp` with the decrypted pixel data.
4.  **Image Assembly:** Use `imagemagick` to horizontally append the three segments: `left.bmp`, `middle_decrypted.bmp`, and `right.bmp`.

## Implementation
A Python script (`solve.py`) was used to perform the XOR operation and reconstruct the middle image:

```python
import sys

BMP_HEADER_SIZE = 138
MIDDLE_BIN_HEADER_SIZE = 160

with open('images/left.bmp', 'rb') as f:
    left_data = f.read()

left_header = left_data[:BMP_HEADER_SIZE]
left_pixels = left_data[BMP_HEADER_SIZE:]

with open('images/middle.bin', 'rb') as f:
    middle_data = f.read()

middle_pixels_encrypted = middle_data[MIDDLE_BIN_HEADER_SIZE:]

decrypted_pixels = bytearray(len(left_pixels))
for i in range(len(left_pixels)):
    decrypted_pixels[i] = left_pixels[i] ^ middle_pixels_encrypted[i]

with open('images/middle_decrypted.bmp', 'wb') as f:
    f.write(left_header)
    f.write(decrypted_pixels)
```

Finally, the images were joined:
```bash
magick convert +append images/left.bmp images/middle_decrypted.bmp images/right.bmp final_image.png
```

## Conclusion
The resulting `final_image.png` displayed the full text, revealing the flag:
**BCCTF{BLoCk_c1pH3r_Mod3}**

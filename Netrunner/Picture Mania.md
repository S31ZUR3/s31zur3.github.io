#Forensics 
## Solution
This is a classic "visual cryptography" or "image layering" challenge. When two images look like random noise, they often contain "shares" of a secret that can be revealed by performing a logical or arithmetic operation between their pixels.

### Investigation
1.  **Analyze Image Properties**: Both images are RGB and have the same dimensions (719x445).
2.  **Combine Shares**: To reveal the hidden content, I tried various image blending methods using the Python Imaging Library (PIL/Pillow).

### Execution
I used the following Python script to calculate the difference between the two images:

```python
from PIL import Image, ImageChops

# Open the two shares
img1 = Image.open('share1.png')
img2 = Image.open('share2.png')

# Calculate the difference
# ImageChops.difference(img1, img2) computes the absolute value of the 
# pixel-by-pixel difference between the two images.
diff = ImageChops.difference(img1, img2)

# Save the result
diff.save('flag.png')
```

### Result
The resulting image `flag.png` clearly showed the text:
**CTF{Picture_in_p1c3}**

## Flag
`CTF{Picture_in_p1c3}`

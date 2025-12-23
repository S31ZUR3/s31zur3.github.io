misc
## Challenge Description
The challenge provided a single file named `blended.txt`. This file contained what appeared to be lines of ASCII art text, but they were scrambled (shuffled) vertically.

## Analysis
1.  **Initial Inspection**: Opening `blended.txt` revealed distinct horizontal slices of large ASCII characters (FIGlet style). Some lines clearly belonged to the top of letters (e.g., starting with ` __`), while others were bottom curves (e.g., `\______/`) or middle sections with vertical bars.

2.  **Reconstruction**:
    - I identified the correct vertical order of the lines by analyzing the structure of standard ASCII art fonts (specifically matching top bars, middle connections, and bottom closures).
    - The correct permutation of the lines (0-based indices from the original file) was determined to be: `[2, 7, 6, 1, 0, 5, 8]`.
    - Applying this reordering reconstructed a readable ASCII art banner.

3.  **Extraction**:
    - The reconstructed banner spelled out a sentence.
    - By carefully reading the ASCII characters, the text was identified as: `UNLP{DOYOULIKEMYGRAFFITY?}`.

4.  **Flag Formulation**:
    - The text "UNLPDOYOULIKEMYGRAFFITY?" was formatted into the standard flag structure.

## Solution
The final flag is:
`UNLP{DOYOULIKEMYGRAFFITY?}`
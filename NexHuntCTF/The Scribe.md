Miscellaneous
## Overview
We are provided with a file named `dump.hex` containing a sequence of hexadecimal values. The goal is to decode these values to retrieve the flag.

## Analysis
Upon inspecting the contents of `dump.hex`, the hex values appeared to correspond to keyboard scan codes. Specifically, they matched the **PS/2 Scan Code Set 1** (XT) protocol.

Key observations:
- Values like `1E`, `1F`, `20` correspond to `a`, `s`, `d` keys.
- Values with the high bit set (e.g., `9E`, `9F`) represent "Break" codes (key releases), which correspond to the "Make" codes (key presses) plus `0x80`.
- Special keys like Shift (`0x2A`/`0x36`) modify the output character.

## Solution

1. **Scripting the Decoder**:
   I created a Python script to parse the hex dump. The script implemented a lookup map for PS/2 Set 1 scan codes.

   The core logic involved:
   - Reading the hex values.
   - Tracking the state of the "Shift" key (Left Shift `0x2A`, Right Shift `0x36`).
   - Translating "Make" codes (key presses) into their ASCII equivalents.
   - Ignoring "Break" codes (except for updating Shift state).

2. **Decoding**:
   Running the decoder on the provided `dump.hex` produced a stream of text resembling a user's typing history. It included Google searches ("youtube: messi skills compilation", "python full course"), chat messages, and coding fragments.

3. **Finding the Flag**:
   Scanning through the decoded text revealed the flag amidst the noise:

   ```
   ...
   echo 'saving credential dump' > output.log
   nexus{1_c4ptur3d_k3y5_wh1l3_w4tch1ng_m3551}
   chmod +x exploit.py
   ...
   ```

## Flag
`nexus{1_c4ptur3d_k3y5_wh1l3_w4tch1ng_m3551}`


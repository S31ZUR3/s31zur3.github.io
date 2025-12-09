crypto
## Challenge Description
We are provided with a file `mtp.txt` containing 10 lines of hex-encoded strings. The title "Parasite" and the file name `mtp.txt` strongly suggest a **Many Time Pad** attack on a stream cipher (like OTP where the key is reused).

## Analysis
In a stream cipher, encryption is performed by XORing the plaintext ($P$) with a key ($K$):
$$C = P \oplus K$$

If the key is reused for multiple messages (as implied by "MTP"), we have:
$$C_1 = P_1 \oplus K$$
$$C_2 = P_2 \oplus K$$

XORing two ciphertexts eliminates the key:
$$C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$$

The result is the XOR sum of the two plaintexts. Since the plaintexts are English text (likely ASCII), we can exploit statistical properties to recover them. For example, the space character (`0x20`) is very frequent. If $P_1$ has a space at index $i$, then:
$$(C_1 \oplus C_2)[i] = \text{space} \oplus P_2[i] = 0x20 \oplus P_2[i]$$
XORing an ASCII letter with `0x20` typically flips its case. This allows us to identify probable spaces and recover the corresponding characters in other messages.

## Solution Steps

1.  **Initial Data Extraction**: We read the hex-encoded lines from `mtp.txt`.
2.  **Automated Analysis**: We wrote a script (`solve_best.py`) that implements a beam search algorithm.
    *   It iterates through each byte position.
    *   For each position, it tries all possible key bytes (0x00-0xFF).
    *   It decrypts that byte for all 10 messages.
    *   It scores the "validity" of the decrypted characters based on English letter frequency and printable ASCII range.
    *   The algorithm keeps the "best" partial keys and extends them.
3.  **Partial Key Recovery**: The script successfully recovered the beginning of the key: `554e4c507b...` which decodes to `UNLP{`. This confirms the key is the flag itself.
4.  **Contextual Refinement**:
    *   The recovered text fragments looked like dialogue.
    *   Msg 0: `You know what kind of plan n...`
    *   Msg 1: ` No plan at all. You know w...`
    *   Searching these phrases online identified them as quotes from the movie **Parasite** (specifically the father's monologue about "no plan").
5.  **Completing the Flag**:
    *   The recovered text fragments looked like dialogue.
    *   We continued to refine the key by guessing the next words in the famous monologue ("Because life cannot be planned", "sleeping together on the floor", etc.).
    *   We used a script `test_key.py` to test our guesses for the flag (Key).
    *   The guess `UNLP{we_4llLiv3inTheS4m3CountryCall3dCapitalism}` resulted in perfectly readable text for all 10 lines.

## Recovered Messages
0. `You know what kind of plan never fails? No plan.`
1. ` No plan at all. You know why? Because life cann`
2. `ot be planned. Look around you. Did you think th`
3. `ese people made a plan to sleep in the sports ha`
4. `ll with you? But here we are now, sleeping toget`
5. `her on the floor. So, there's no need for a plan`
6. `. You can't go wrong with no plans. We don't nee`
7. `d to make a plan for anything. It doesn't matter`
8. ` what will happen next. Even if the country gets`
9. ` destroyed or sold out, nobody cares. Got it?`

## Final Flag
`UNLP{we_4llLiv3inTheS4m3CountryCall3dCapitalism}`
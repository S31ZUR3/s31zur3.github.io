rev

Analysis:
1.  The challenge involves reverse engineering the provided `my_secret_recipe` binary.
2.  Executing the binary without arguments reveals its usage: `./my_secret_recipe <FLAG_STR>`. This suggests it validates a flag string.
3.  Initial `strings` analysis reveals a long "recipe" text and success/failure messages, along with several words that appear to be ingredients or cooking actions. It also reveals function names like `parse_recipe` and `normalize_word`.
4.  Disassembly of the `main` function shows that it takes the user-provided `<FLAG_STR>`, calls `parse_recipe` with a hardcoded "recipe" string, and then compares the result of `parse_recipe` with the user's input using `strcmp`. If they match, it prints a success message and the flag.
5.  Disassembly of `parse_recipe` reveals the core logic:
    *   It tokenizes the hardcoded recipe string using space and newline characters as delimiters.
    *   For each token (word), it calls `normalize_word` (which was not explicitly analyzed, but likely handles case or punctuation).
    *   It then iterates through an array of ingredient structures. Each structure contains a pointer to an ingredient name (string) and a pointer to a small function.
    *   If a token from the recipe matches an ingredient name, the corresponding function pointer is called.
    *   These small functions (e.g., `bake`, `perfect`, `sift`) simply load a specific byte into the `eax` register and return.
    *   The returned byte (character) is then stored into a dynamically calculated offset in a buffer. The offset is determined by the index of the matched ingredient in the `ingredients` array.
6.  By inspecting the `.data` and `.rodata` sections of the binary, the `ingredients` array was extracted. It was found to contain 41 entries (indices 0-40).
7.  Each ingredient name and its corresponding function's return value (character) were mapped.
8.  It was determined that all 41 ingredients in the `ingredients` array are present in the hardcoded recipe text in the correct order. Therefore, the flag is simply the concatenation of the characters returned by each ingredient's function, in the order they appear in the `ingredients` array.

Flag Construction:
The flag was reconstructed by iterating through the 41 ingredients and collecting the character returned by their associated functions.

| Index | Ingredient | Function Address | Returned Byte (Hex) | Character |
| :--- | :--------- | :--------------- | :------------------ | :-------- |
| 0 | bake | 0x11a9 | 0x48 | H |
| 1 | perfect | 0x11b4 | 0x65 | e |
| 2 | sift | 0x11bf | 0x72 | r |
| 3 | flour | 0x11ca | 0x6f | o |
| 4 | sugar | 0x11d5 | 0x7b | { |
| 5 | crack | 0x11e0 | 0x30 | 0 |
| 6 | eggs | 0x11eb | 0x68 | h |
| 7 | melt | 0x11f6 | 0x5f | _ |
| 8 | butter | 0x1201 | 0x4e | N |
| 9 | blend | 0x120c | 0x30 | 0 |
| 10 | vanilla | 0x1217 | 0x5f | _ |
| 11 | milk | 0x1222 | 0x79 | y |
| 12 | whisk | 0x122d | 0x30 | 0 |
| 13 | cocoa | 0x1238 | 0x75 | u |
| 14 | fold | 0x1243 | 0x5f | _ |
| 15 | baking | 0x124e | 0x36 | 6 |
| 16 | powder | 0x1259 | 0x30 | 0 |
| 17 | swirl | 0x1264 | 0x54 | T |
| 18 | cream | 0x126f | 0x5f | _ |
| 19 | chop | 0x127a | 0x4d | M |
| 20 | cherry | 0x1285 | 0x79 | y |
| 21 | toss | 0x1290 | 0x5f | _ |
| 22 | sprinkles | 0x129b | 0x53 | S |
| 23 | preheat | 0x12a6 | 0x33 | 3 |
| 24 | oven | 0x12b1 | 0x63 | c |
| 25 | grease | 0x12bc | 0x52 | R |
| 26 | pan | 0x12c7 | 0x65 | e |
| 27 | line | 0x12d2 | 0x54 | T |
| 28 | parchment | 0x12dd | 0x5f | _ |
| 29 | timer | 0x12e8 | 0x43 | C |
| 30 | light | 0x12f3 | 0x34 | 4 |
| 31 | candle | 0x12fe | 0x6b | k |
| 32 | plate | 0x1309 | 0x33 | 3 |
| 33 | garnish | 0x1314 | 0x5f | _ |
| 34 | frosting | 0x131f | 0x52 | R |
| 35 | pinch | 0x132a | 0x33 | 3 |
| 36 | salt | 0x1335 | 0x63 | c |
| 37 | crushed | 0x1340 | 0x31 | 1 |
| 38 | nuts | 0x134b | 0x70 | p |
| 39 | touch | 0x1356 | 0x65 | e |
| 40 | sweetness | 0x1361 | 0x7d | } |

Final Flag:
`Hero{0h_N0_y0u_60T_My_S3cReT_C4k3_R3c1pe}`

[[HeroCTF 2025]]
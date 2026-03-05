#Rev 
### Virtual Machine Reversing
Disassembling the binary reveals a custom VM dispatcher. The VM uses several registers:
- `reg[0]`: Input character (from `getchar`).
- `reg[1]`: X-coordinate (starts at 1).
- `reg[2]`: Y-coordinate (starts at 1).
- `reg[3]`: Insight (starts at 0).

#### Instruction Set
- `0x10`: `MOV REG, VAL`
- `0x20`: `ADD REG, VAL`
- `0x30`: `SUB REG, VAL`
- `0x40`: `CMP REG, VAL`
- `0x50`: `JMP ADDR`
- `0x51`: `JZ ADDR`
- `0x52`: `JNZ ADDR`
- `0x60`: `GETCHAR` (Reads input into `reg[0]`)
- `0xee`: `SUCCESS` (Prints the flag)
- `0xff`: `EXIT`

### Input Logic
The VM processes characters as movement commands:
- `'r'` (0x72): `X++` (reg[1])
- `'l'` (0x6c): `X--` (reg[1]) and `Insight++` (reg[3])
- `'u'` (0x75): `Y++` (reg[2])
- `'d'` (0x64): `Y--` (reg[2])

### Winning Conditions
The bytecode (found at `.data + 0x20`) defines the logic for "opening the portal":
1. **Boundary Check:** `X` and `Y` must stay between 1 and 12. If `X` or `Y` becomes 0 or 13, the program exits.
2. **The Portal:**
   - If `X == 6` and `Y == 6`, Insight must be at least 5 to proceed.
   - The final gate is at `X == 12` and `Y == 12`.
   - To open the final gate, **Insight must be exactly 7**.

## Solution Strategy
To reach the portal at (12, 12) with 7 Insight without hitting boundaries:
1. **Generate Insight:** Move left (`l`) 7 times to increment Insight to 7. Since we start at `X=1`, we must move right (`r`) first to avoid hitting `X=0`.
   - Ritual: `rlrlrlrlrlrlrl` (7 pairs of Right-Left moves). This results in `X=1, Y=1, Insight=7`.
2. **Navigate to Portal:** From `(1, 1)`, move to `(12, 12)`.
   - Move Right 11 times: `rrrrrrrrrrr` (`X=12`).
   - Move Up 11 times: `uuuuuuuuuuu` (`Y=12`).
3. **Sequence:** `rlrlrlrlrlrlrlrrrrrrrrrrruuuuuuuuuuu`

## Execution
```bash
echo "rlrlrlrlrlrlrlrrrrrrrrrrruuuuuuuuuuu" | nc netrunner.kurukshetraceg.org.in 5019
```

**Flag:** `CTF{11_steps_t0_th3_v0id}`

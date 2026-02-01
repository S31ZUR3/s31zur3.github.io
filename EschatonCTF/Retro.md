#Rev 
## 1. Initial Reconnaissance

Started by inspecting the file to confirm it was a valid Game Boy ROM and to look for interesting strings.

```bash
file retro.gb
strings retro.gb | head -n 20
```

**Findings:**
- Valid Game Boy ROM image.
- Strings like "RETRO" (Title), "GEEEEH" (Fake Flag), and "W D W D" (Likely True Flag).
- Header Checksum was valid (`0x27`), indicating the file wasn't just a corrupt download, but intentionally obfuscated.

## 2. Code Analysis

Disassembling the entry point and following the execution flow revealed a simple state machine driven by a variable at memory address `[0xC000]`.

### The State Machine
The code at `0x22E` acts as a dispatcher, jumping to different routines based on `[0xC000]`:

- **State 0 (Default):** Runs the "Zelda" title screen.
- **State 1 (`[0xC000] = 1`):** Runs Routine 2 (Found at `0x300`), displaying "GEEEEH..." (The Fake Flag).
- **State 2 (`[0xC000] = 2`):** Runs Routine 3 (Found at `0x410`), displaying "W D W D..." (The True Flag).

### The Obstacles
To reach State 2, the program required specific conditions to be met, but the code paths to satisfy them were blocked by `RET` (Return) instructions.

1.  **Blocked Sub-Flags:**
    - Code at `0x1D9` sets `[0xC001] = 1`.
    - Code at `0x1F7` sets `[0xC002] = 1`.
    - **Problem:** Both were preceded by `RET` instructions at `0x1D8` and `0x1F6`, making them unreachable.

2.  **Blocked State Transition:**
    - Code at `0x20E` checks if both `[0xC001]` and `[0xC002]` are 1.
    - If true, it proceeds to set `[0xC000] = 2` (The Flag State).
    - **Problem:** This check was guarded by a `RET` at `0x20D` and another `RET` at `0x21A`, preventing the state switch even if the flags were set.

## 3. The Solution (Patching)

Applied patches in two stages to remove the `RET` instructions, replacing them with `NOP` (No Operation, `0x00`) to allow execution flow to continue.

### Patch 1: Enabling Sub-Flags
Removed the returns blocking the setup of the two required condition flags.

- **0x1D8:** `C9` (RET) -> `00` (NOP)
- **0x1F6:** `C9` (RET) -> `00` (NOP)

*Result:* This allowed `[0xC001]` and `[0xC002]` to be set to 1.

### Patch 2: Unlocking the Flag State
Removed the returns blocking the verification logic and the final state switch.

- **0x20D:** `C9` (RET) -> `00` (NOP)
- **0x21A:** `C9` (RET) -> `00` (NOP)

*Result:* The program can now verifying that `[0xC001]` and `[0xC002]` are set, and subsequently set `[0xC000] = 2`.

### 4. Checksum Correction
Game Boy hardware and emulators verify the ROM header checksum. After modifying bytes, this checksum became invalid. Wrote a script to recalculate the header checksum (bytes `0x134`-`0x14C`) and the global checksum, updating the file to ensure it loads correctly.
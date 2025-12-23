rev
## 1. Initial Analysis

We start by inspecting the provided files. `ngawari_vm` is the executable, and `flag_checker.txt` contains unintelligible text data.

Running `strings` on the binary reveals that it is a "generalized, programmable input checker". Key strings include:

- `Ngawari VM - A generalized, programmable input checker`
    

- `Required first line of file missing`
    

- `Input accepted!`
    

- `Stack overflow` / `Stack underflow`
    

This suggests the binary implements a stack-based virtual machine that reads `flag_checker.txt` as a set of rules.

## 2. Reverse Engineering the VM logic

Using `gdb` (GNU Debugger), we analyzed the `accept_input` function, which is the core execution loop. The disassembly revealed that the VM operates as a **Pushdown Automaton (PDA)**.

A PDA is a theoretical machine that uses a **Stack** and a **State** to decide valid transitions. The disassembly showed that for every input character, the VM performs the following check:

δ(CurrentState,InputChar,PopStack)→(NextState,PushString)

Specifically, the VM reads instructions from `flag_checker.txt` and looks for a line that matches:

1. **Current State:** The VM's current state byte.
    
2. **Input Character:** The character you just typed.
    
3. **Stack Top:** The character popped from the top of the stack.
    

If a match is found, the VM transitions to the **Next State** and pushes a defined string onto the stack.

## 3. Decoding `flag_checker.txt`

With the logic understood, we can parse `flag_checker.txt`.

### The Header

The first line of the file is `aBw`.

- `a`: **Initial State**.
    
- `B`: **Initial Stack Symbol** (The stack starts with this char).
    
- `w`: **Accepting State** (The state we must reach to win).
    

### The Instructions

Subsequent lines follow a specific format. Take the line `i_GoPHER` as an example:

- `i`: **Current State** required.
    
- `_`: **Input Character** required.
    
- `G`: **Stack Pop** required (Must be at the top of the stack).
    
- `o`: **Next State**.
    
- `PHER`: **String to Push**.
    
    - _Note:_ The VM loops through this string and pushes characters. Effectively, the first character of the string (`P`) becomes the new top of the stack.
        

## 4. Solving the Automaton

The complexity of the stack operations makes manual solving impossible. We need to find a path from the start state `a` (with stack `['B']`) to the target state `w`.

We can solve this using a Breadth-First Search (BFS) algorithm in Python. The script simulates the PDA, tracking the `(State, Stack)` tuple to find the correct path.

### The Solver Script

Python

```
import collections

def solve_vm():
    # Load the bytecode
    with open('flag_checker.txt', 'r') as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]

    # Parse Header: aBw
    # Init State: 'a', Init Stack: 'B', Target State: 'w'
    header = lines[0]
    init_state = header[0]
    init_stack = (header[1],) # Represent stack as a tuple
    target_state = header[2]

    # Parse Transitions
    transitions = []
    for line in lines[1:]:
        if len(line) < 4: continue
        # Format: [State][Input][Pop][NextState][PushStr...]
        transitions.append({
            'state': line[0],
            'in_char': line[1],
            'pop_char': line[2],
            'next_state': line[3],
            'push_str': line[4:] 
        })

    # BFS Initialization
    # Queue stores: (Current State, Current Stack Tuple, Path Taken)
    queue = collections.deque([(init_state, init_stack, "")])
    visited = set([(init_state, init_stack)])
    
    print("Searching for flag...")

    while queue:
        curr_state, curr_stack, history = queue.popleft()

        # The stack cannot be empty for a valid move
        if not curr_stack:
            continue
            
        # Get the top of the stack
        top_of_stack = curr_stack[-1]
        stack_body = curr_stack[:-1]

        for t in transitions:
            # Check if this transition applies
            if t['state'] == curr_state and t['pop_char'] == top_of_stack:
                
                # Check for Win Condition
                # The VM terminates input with a '^' char. 
                if t['in_char'] == '^':
                    if t['next_state'] == target_state:
                        return history # Return the path (the flag)
                    continue

                # Execute the move
                # 1. Pop is already done (we separated top_of_stack)
                # 2. Push the new string (reversed so first char is new top)
                new_push = tuple(t['push_str'][::-1])
                new_stack = stack_body + new_push
                new_state = t['next_state']
                
                # Add to queue if not visited
                state_signature = (new_state, new_stack)
                if state_signature not in visited:
                    visited.add(state_signature)
                    # Append the input char to our history
                    queue.append((new_state, new_stack, history + t['in_char']))

    return "Flag not found."

print(f"Flag: {solve_vm()}")
```

## 5. The Result

Running the solver simulates the machine steps and recovers the input string that satisfies the "Accepting State" condition.

**Flag:**

Plaintext

```
VuwCTF{VuwCTF_1s_s0_c00l_innit}
```
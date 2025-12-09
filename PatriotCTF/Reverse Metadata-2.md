misc
## 1. Executive Summary

After achieving initial Remote Code Execution (RCE) via an image polyglot upload, the objective was to locate a "deleted" flag hidden on the system. While the challenge environment contained a vulnerable Cron Job running `exiftool` as root (suggesting a CVE-2021-22204 exploit path), we discovered the flag exposed in plain text within the process list. The vulnerability stemmed from passing sensitive data (the flag) directly into command-line arguments, which are readable by all users on standard Linux configurations.

## 2. Initial Access

We established a foothold on the server as the `www-data` user by uploading a malicious PHP file disguised as a JPEG image (`cat.php`). This allowed us to execute system commands via the browser.

## 3. Enumeration

We began standard Linux enumeration to identify background services, looking for the script mentioned in the challenge description ("processes uploaded images... every few minutes").

We ran the process list command to see what was running as **root**:

Bash

```
ps -aux | grep root
```

## 4. The Discovery

The output of the process list revealed a critical security flaw. Instead of running a python script from a file (e.g., `python3 /root/script.py`), the root user was running a Python "one-liner" passed directly via the `-c` command argument.

**Output:**

Plaintext

```
root      15  0.0  0.0  12136  7964 ?        S    08:30   0:00 python3 -c  import time, os  FLAG="/tmp/flag.txt"  # create flag file f = open(FLAG, "w") f.write("PCTF{hidden_in_depths}\n") f.flush()  # unlink instantly (file disappears from /tmp) os.unlink(FLAG)  # keep process alive so FD stays in RAM while True:     time.sleep(100)
```

### Breakdown of the Vulnerable Script:

1. **`f.write("PCTF{hidden_in_depths}\n")`**: The flag was hardcoded into the script logic.
    
2. **`os.unlink(FLAG)`**: The script immediately deleted the file from the disk. This effectively prevented us from finding it using `ls` or `find`.
    
3. **`while True: time.sleep(100)`**: The script kept running indefinitely to keep the process alive.
    

## 5. The Vulnerability: Command Line Argument Leaks

On Linux systems, the full command line used to start a process is stored in `/proc/[PID]/cmdline`. By default, any user (including our low-privileged `www-data` user) can read the process list and arguments of other users, including root.

Because the developer included the **source code** (containing the flag) in the command arguments (`python3 -c "..."`), the flag was leaked to the process table.

## 6. Conclusion & Mitigation

We successfully retrieved the flag `PCTF{hidden_in_depths}` without needing to escalate privileges or exploit the ExifTool vulnerability.

**Intended Solution vs. Our Solution:**

- **Intended:** Exploit the root cron job running `exiftool` (CVE-2021-22204) to copy the deleted file from `/root/.local/share/Trash`.
    
- **Actual:** Found the flag in the process listing due to insecure scripting practices.
    

**Remediation:** To prevent this, secrets should never be passed as command-line arguments. The script should have been saved to a file (readable only by root) and executed as `python3 /path/to/script.py`. Additionally, server hardening (mounting `/proc` with `hidepid=2`) would prevent users from seeing processes belonging to other users.


[[PatriotCTF-2025]]
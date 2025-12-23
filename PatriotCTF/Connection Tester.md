web

**Writeup for "Connection Tester" challenge:**

1.  **Initial Reconnaissance:** Accessed `http://18.212.136.134:9080/`. It redirected to `/login`.
2.  **Authentication Bypass (SQL Injection):**
    *   Inspected the `/login` page and found a standard username/password form.
    *   Attempted SQL injection with `username=' OR 1=1 --` and `password=password`.
    *   Login was successful, redirecting to `/dashboard`.
3.  **Session Management:**
    *   Used `curl -c cookies.txt` to save the session cookie after successful login.
    *   Accessed `/dashboard` using `curl -b cookies.txt`.
4.  **Command Injection Discovery:**
    *   The dashboard presented a "Connectivity Tester" with a "Target Address" input.
    *   This is a classic command injection vector.
    *   Tested with `address=127.0.0.1; ls`. The output indicated `ls...: not found`, suggesting an appended `...`.
5.  **Command Injection Exploitation:**
    *   Used `address=127.0.0.1; ls -la #` to comment out the appended `...`.
    *   Successfully executed `ls -la` and obtained a directory listing, revealing `flag.txt`.
    *   Used `address=127.0.0.1; cat flag.txt #` to read the flag.
6.  **Flag:** `PCTF{C0nn3cti0n_S3cured}`
   
   [[PatriotCTF-2025]]
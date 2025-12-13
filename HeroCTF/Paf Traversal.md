pwn
## 1. Initial Reconnaissance

The challenge presented a set of files including a `cracker` directory (with `main.c` and `Makefile`) and an `api` directory (with Go files). The initial assumption was a local pwnable binary.

- `cracker/main.c`: Contained the C code for a hash cracking service.
- `api/`: Contained Go source code for a web API.

## 2. `cracker` Binary Analysis

Analysis of `cracker/main.c` revealed a program that communicates via named pipes (`/tmp/cracker.in` and `/tmp/cracker.out`). It accepts three lines of input:
1.  `<algo_type>`: Hashing algorithm (MD5, SHA1, SHA256).
2.  `<hash_hex>`: Target hash.
3.  `<wordlist_path>`: Path to a wordlist file.

The program then reads lines from `wordlist_path`, hashes them, and compares them to the target hash. A critical vulnerability was identified: the `wordlist_path` parameter was directly used in `fopen(wordlist_str, "r")` without sanitization, indicating a **path traversal vulnerability**.

The `Makefile` showed compilation with debug symbols (`-g`) and no optimizations (`-O0`).

## 3. Web Interface Discovery

Initial attempts to interact with the local `cracker` binary directly proved difficult due to the interactive nature of the FIFO communication and the agent's limitations with concurrent shell commands. The user's prompt `http://dyn12.heroctf.fr:10259/` clarified that this was a remote web-based challenge.

Accessing the URL via `curl http://dyn12.heroctf.fr:10259/` revealed a "Wordlist & Bruteforce Dashboard" web interface. This suggested that the `api` Go application was serving this interface and likely interacting with the `cracker` binary in the background.

## 4. `app.js` Analysis

To understand the web application's interaction with the backend, `app.js` was retrieved: `curl http://dyn12.heroctf.fr:10259/assets/app.js`.

The `app.js` file revealed key API endpoints:
-   `/api/wordlist` (GET): List wordlists.
-   `/api/wordlist` (POST): Upload wordlist.
-   `/api/wordlist` (DELETE): Delete wordlist.
-   `/api/wordlist/download` (POST): **Download wordlist content.** This endpoint was particularly interesting.
-   `/api/bruteforce` (POST): Start a bruteforce job.

## 5. Path Traversal in `HandleDownloadWordlist`

Further investigation focused on `api/controllers/wordlist_controller.go`. The `HandleDownloadWordlist` function was found to handle the `/api/wordlist/download` endpoint.

The relevant code snippet:
```go
func HandleDownloadWordlist(c *gin.Context) {
    wordlistDir := getWordlistDir() // e.g., /app/api/wordlists/
    json := DownloadRequest{}
    if err := c.ShouldBindJSON(&json); err != nil { /* ... */ }

    filePath := filepath.Join(wordlistDir, json.Filename) // Vulnerable line!
    f, err := os.Open(filePath) // Error originates here
    if err != nil { /* ... */ }
    defer f.Close()

    data, err := io.ReadAll(f)
    if err != nil { /* ... */ }

    c.JSON(http.StatusOK, gin.H{ "filename": fileName, "content": string(data), })
}
```
Crucially, `filePath` was constructed using `filepath.Join(wordlistDir, json.Filename)`. While `filepath.Join` normally handles absolute paths correctly (if `json.Filename` were `/flag.txt`, `filePath` should become `/flag.txt`), initial attempts with `{"filename": "/flag.txt"}` resulted in `{"error":"open /app/api/wordlists/flag.txt: no such file or directory"}`. This indicated that `json.Filename` was being treated as a relative path, or the `wordlistDir` was being prepended despite the absolute path.

However, using path traversal techniques like `../` proved successful. A request with `{"filename": "../../../../flag.txt"}` resulted in `{"error":"open /flag.txt: no such file or directory"}`, confirming that we could reach the root directory (`/`).

## 6. Path Traversal in `HandleBruteforce` (and why it wasn't vulnerable)

Analysis of `api/controllers/bruteforce_controller.go` showed that the `StartBruteforce` function handled the `/api/bruteforce` endpoint. While the `cracker` binary itself was vulnerable to path traversal through `wordlist_str`, the Go API sanitized the `wordlist` parameter before passing it to the `cracker`.

```go
filePath := filepath.Join(wordlistDir, path.Base(json.Wordlist)) // `path.Base` strips traversal!
resp, err := requestAndWait(json.Algorithm, json.Hash, filePath, DEFAULT_TIMEOUT)
```
The `path.Base()` call effectively removed any `../` sequences, making this endpoint not vulnerable to path traversal.

## 7. Flag Location Discovery (`entrypoint.sh`)

With confirmed path traversal via `/api/wordlist/download`, the next step was to find the flag. Common CTF flag locations (`/flag.txt`, `/etc/flag`, `/app/flag.txt`, `/var/www/html/flag.txt`) were attempted but returned "no such file or directory".

Attempting to read `/.dockerenv` using `{"filename": "../../../.dockerenv"}` returned empty content but confirmed that arbitrary file reading from the root was possible.

The `entrypoint.sh` script is often a good place to look for flag setup in Docker containers. Reading `/entrypoint.sh` via `{"filename": "../../../entrypoint.sh"}` yielded:

```bash
#!/bin/bash

echo "${FLAG:-HEROCTF_FAKE_FLAG}" > "/app/flag_$(openssl rand -hex 8).txt"
chmod 444 /app/flag_*.txt
unset FLAG

/app/cracker/cracker &
cd /app/api/ && ./api
```
This script revealed:
- The flag is written to `/app/flag_RANDOMHEX.txt`, where `RANDOMHEX` is a random 8-byte hexadecimal string generated by `openssl rand -hex 8`.
- The `FLAG` environment variable is `unset` *after* the file is created.

This meant the flag filename was dynamic and unpredictable.

## 8. Finding the Random Flag

Since the flag filename was random and directory listing was not possible via the `download` endpoint, a new approach was needed. The `entrypoint.sh` script set the `FLAG` environment variable *before* writing it to the file and then unsetting it.

In Docker containers, the process with PID 1 is typically the `entrypoint.sh` script or its direct parent. The environment variables of a process can often be read from `/proc/<pid>/environ`.

Therefore, the strategy was to read the environment variables of PID 1, hoping to find the `FLAG` before it was unset.

Requesting `{"filename": "../../../proc/1/environ"}` via the `/api/wordlist/download` endpoint:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"filename": "../../../proc/1/environ"}' http://dyn12.heroctf.fr:10259/api/wordlist/download
```

## 9. Final Flag Retrieval

The response to the `/proc/1/environ` request contained the following:

```json
{"content":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000HOSTNAME=paf_traversal\u0000FLAG=Hero{e9e2b63a0daa9ee41d2133b450425b2cd7c7510e5a28b
655748456bd3f6e5c2a}\u0000DEPLOY_HOST=dyn12.heroctf.fr\u0000DEPLOY_PORTS=8000/tcp-\u003e10259\u0000HOME=/app/\u0000","filename":"environ"}
```

The `FLAG` environment variable was successfully extracted!

**The Flag: `Hero{e9e2b63a0daa9ee41d2133b450425b2cd7c7510e5a28b655748456bd3f6e5c2a}`**

[[HeroCTF 2025]]

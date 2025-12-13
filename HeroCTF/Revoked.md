web
## Initial Analysis (from main.py)

1.  **Tech Stack**: Flask, SQLite, bcrypt, PyJWT.
2.  **Authentication**: Uses JWTs stored in cookies. Tokens are signed with a randomly generated `SECRET_KEY` on server startup.
3.  **Authorization**: The `@token_required` decorator checks the JWT. It decodes the token, extracts the `username`, and then queries the database (`SELECT id,is_admin FROM users WHERE username = ?`) to re-validate the user's existence and `is_admin` status. If `is_admin` is True, access is granted.
4.  **Revocation**: Tokens can be revoked by logging out. Revoked tokens are stored in the `revoked_tokens` SQLite table. The `@token_required` decorator checks this table to invalidate revoked tokens.
5.  **User Creation**: The `/register` route hardcodes `is_admin=False` for all new users.
6.  **SQL Injection**: A clear SQL Injection vulnerability was identified in the `/employees` route:
    ```python
    cursor.execute(f"SELECT id, name, email, position FROM employees WHERE name LIKE '%{query}%'")
    ```
    This allowed arbitrary `UNION SELECT` statements.

## Exploitation Steps

### 1. Identify Target and Data Exfiltration
*   The goal was to access the `/admin` route, which required `is_admin=True`.
*   Initial analysis showed no way to register an admin user or forge a JWT (due to random `SECRET_KEY`).
*   The SQL Injection in `/employees` was leveraged to dump database contents.

### 2. Dump `users` Table and Schema
*   A custom `exploit.py` script was created to automate interaction with the web application.
*   The script registered a new user, logged in to obtain a valid (non-admin) JWT.
*   Using the SQL Injection, the `users` table was dumped:
    ```sql
    ' UNION SELECT id, username, password_hash, is_admin FROM users --
    ```
*   This revealed two administrative users: `admin` and `admin1`, both with `is_admin=1` and bcrypt password hashes.
    *   `admin`: `$2b$12$paAeWwE7G3kMbKd9V2344.VheW.CY4CEvw6MpB18ce9ACKYvwo5We`
    *   `admin1`: `$2b$12$2Gongni0OWKE.kgVxUcSPuKv6m05tY1WvHGMIVCenUymB2k/cTXpS`
*   Attempted cracking of these bcrypt hashes with common password lists failed, indicating strong passwords or non-standard choices.

### 3. Focus on "Revoked" - Dump `revoked_tokens` Table
*   Given the challenge name "Revoked", attention shifted to the `revoked_tokens` table.
*   The `revoked_tokens` table was dumped using SQL Injection:
    ```sql
    ' UNION SELECT id, id, 'dummy', token FROM revoked_tokens --
    ```
*   This revealed several revoked tokens, including one for the `admin` user:
    ```
    Revoked Token ID: 2 | Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlzc3VlZCI6MTc2NDQyMjkwOC45NjM4MDY0fQ.4CGjZX4VVJR8clWviAdL8SYL3yP29wI30D2kcTCmPCs
    ```
*   Decoding this JWT confirmed its payload: `{"username":"admin","is_admin":1,"issued":1764422908.9638064}`. This was a valid token for an admin user, but it was marked as revoked in the database.

### 4. JWT Revocation Bypass (Padding Mismatch)

*   The key to bypassing the revocation check lay in a subtle difference in how `PyJWT` (the Python JWT library) and SQLite handle Base64URL string comparison.
*   `PyJWT` is flexible with Base64 padding. It will often accept a Base64URL string even if it has incorrect or absent padding characters (`=`).
*   SQLite's string comparison (used in `SELECT ... WHERE token = ?`) is typically strict and requires an exact match.
*   **Hypothesis**: If the revoked token was stored in `revoked_tokens` without padding, providing the *same* token with padding (`=`) might allow it to be decoded by `PyJWT` (thus passing signature verification) but *not* matched by SQLite's strict equality check against the stored (unpadded) revoked token. This would cause the `revoked` flag in the `token_required` decorator to be `None`, effectively bypassing the revocation check.
*   The raw revoked token did not have padding. Appending a single `=` to the base64-encoded signature part of the token was attempted.

### 5. Final Exploit

*   The revoked `admin` JWT was taken: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlzc3VlZCI6MTc2NDQyMjkwOC45NjM4MDY0fQ.4CGjZX4VVJR8clWviAdL8SYL3yP29wI30D2kcTCmPCs`
*   A padding character (`=`) was appended to it: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImlzc3VlZCI6MTc2NDQyMjkwOC45NjM4MDY0fQ.4CGjZX4VVJR8clWviAdL8SYL3yP29wI30D2kcTCmPCs=`
*   This modified token was then used as the `JWT` cookie to request the `/admin` route.
*   The request returned a `200 OK` status, and the HTML content included the flag.

## Flag
`Hero{N0t_th4t_r3v0k3d_ec6dcf0ae6ae239c4d630b2f5ccb51bb}`

[[HeroCTF 2025]]


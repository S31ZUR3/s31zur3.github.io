web

1. Challenge Description:
The challenge involved a web application written in Pony, accessible via a provided set of Docker files and source code. The goal was to retrieve a flag from a protected endpoint.

2. Vulnerability Identified:
The core vulnerability was a logic error in the `/flag` endpoint's access control. The `F` request handler in `app/main.pony` was responsible for serving the flag. It had two main checks:
   - The `Host` HTTP header must be `127.0.0.1`.
   - The request URI path (`ctx.request.uri().string()`) must NOT be exactly `"/flag"` or `"flag"`.

The flaw lies in the second condition. While the Jennet web framework routes requests to `/flag` to this handler, the `ctx.request.uri().string()` method returns the full URI, including any query parameters. Therefore, a request to `/flag?anything` would still be routed to the `F` handler, but the `path` variable inside the handler would be `"/flag?anything"`, which does not match `"/flag"` or `"flag"`, thus bypassing the intended restriction.

3. Exploitation Steps:
To exploit this, the following steps were taken:
   a.  **Identify the target:** The remote server URL was `http://public.ctf.r0devnull.team:3002/`.
   b.  **Spoof the Host header:** Set the `Host` header to `127.0.0.1`.
   c.  **Bypass path check:** Append a query string to the `/flag` endpoint (e.g., `?x`).

The command used was:
`curl -H "Host: 127.0.0.1" "http://public.ctf.r0devnull.team:3002/flag?x"`

4. Flag:
The flag obtained was:
`nullctf{p3rh4ps_my_p0ny_!s_s0mewh3re_3lse_:(`
web
## Challenge Overview
The challenge provided a Next.js application implementing JWT-based authentication. The goal was to retrieve a flag protected by an admin check.                                                                                                                                    ## Vulnerabilities Identified

### 1. Insecure Middleware Scope & Logic
The `middleware.js` file was configured to match only `/api/:path*` routes:
```javascript
export const config = {                                                                         matcher: '/api/:path*',
};
```                                                                                         This left the token generation endpoint `/token/sign` (located at `app/token/sign/route.js`) exposed. Anyone could request this endpoint to generate a valid signed JWT for a non-admin user (e.g., "guest").

### 2. JWT Algorithm Confusion                                                              The verification logic in `app/token/verify/route.js` insecurely allowed multiple algorithms:
```javascript                                                                               function verifyToken(token) {
    return jwt.verify(token, PUBKEY, { algorithms: ['RS256', 'HS256'] });
}
```
The server uses a Public Key (`PUBKEY`) to verify tokens. Standard tokens are signed with a Private Key using `RS256`. However, by allowing `HS256` (HMAC with SHA-256), the library treats the key provided (`PUBKEY`) as a *symmetric secret*.

This allows an attacker to sign a malicious token using `HS256` and the *Public Key* as the secret. The server, validating with the same Public Key and allowing `HS256`, will verify the signature as valid.
                                                                                            ## Exploit Chain

1. **Obtain Valid "Guest" Token**
   - We bypassed the middleware protection by hitting the exposed `/token/sign` endpoint.
   - **Payload:** `{"username": "guest"}`
   - **Result:** A valid RS256 signed token.

2. **Retrieve Public Key**
   - The endpoint `/api/getPublicKey` is protected by middleware but allows access to users with a valid token.
   - We sent a request to `/api/getPublicKey` with the valid "guest" token in the cookies.
   - **Result:** The server returned its Public Key.

3. **Forge Admin Token**
   - We created a new JWT with the payload `{"username": "admin"}`.
   - We signed this token using the **HS256** algorithm, using the retrieved **Public Key** as the secret key.
   - Code snippet:
     ```javascript
     jwt.sign({ username: 'admin' }, publicKey, { algorithm: 'HS256' });
     ```

4. **Retrieve Flag**
   - We sent the forged admin token to `/api/getFlag`.
   - The server verified the token (believing it to be valid because the signature matched the Public Key processed as an HMAC secret) and saw `username: "admin"`.
   - **Result:** The server returned the flag.

## Flag
`nullctf{f0rg3_7h15_cv3_h3h_a44452394d983966}`
web

## Vulnerability Analysis
The application implemented an email normalization feature, hinted at by the client-side JavaScript that checked for non-ASCII characters and called `/api/normalize_email`. This suggested that the backend might be performing Unicode normalization (likely NFKC or similar) on email addresses.

Testing confirmed:
- `ａ` (Full-width Latin Small Letter A) -> `a`
- `ﬁ` (Latin Small Ligature Fi) -> `fi`
- `ı` (Latin Small Letter Dotless I) -> `i`

The application prevented registering or changing the email to `admin@shazctf.com` directly ("Email already taken"), indicating an existing admin account used that email.

## Exploitation Steps
1. **Account Creation**: Registered a new account with a random username (`myadmin`) and email.
2. **Homograph Attack**: Logged in and navigated to the dashboard to change the email address.
3. **Bypass Duplicate Check**: Attempted to change the email to `admın@shazctf.com` using the "Latin Small Letter Dotless I" (`ı`).
   - The application accepted this email because `admın@shazctf.com` is string-distinct from `admin@shazctf.com`.
   - However, the backend normalization logic (likely running on login or privilege checks) normalized `admın@shazctf.com` to `admin@shazctf.com`.
4. **Privilege Escalation**:
   - After successfully changing the email, I logged out and logged back in.
   - The session refresh presumably updated the user's role or access rights based on the normalized email address matching the admin's email.
5. **Flag Retrieval**: Accessed the `/flag` endpoint, which was previously forbidden (403), and retrieved the flag.

## Flag
`ShaZ{y0u_3xpl0it3d_7h3_punny_c0d3_0_cl1ck_ATO}`
web
## Vulnerability Analysis
1.  **Initial Access**:
    *   Logged in using the credentials `user` / `pass`.
    *   The application redirected to `/blog`.

2.  **Reconnaissance**:
    *   The `/blog` page source code revealed a "View My Profile (JSON)" link pointing to `/viewProfile/uuid/fa4308d8-9142-4943-88aa-cd9fa6391f0f`.
    *   The page also displayed an "Admin" user with a profile picture located at `/uuid/90c3507d-09bb-43cb-8a2c-a5d3a72b06cc/profile.jpg`.
    *   This leaked the Admin's UUID: `90c3507d-09bb-43cb-8a2c-a5d3a72b06cc`.

3.  **Exploitation Attempt (IDOR)**:
    *   I attempted to view the admin's profile by replacing my UUID with the Admin's UUID in the API endpoint:
        `http://34.14.220.175:4000/viewProfile/uuid/90c3507d-09bb-43cb-8a2c-a5d3a72b06cc`
    *   The server returned a `403 Forbidden` error, indicating a server-side check preventing access to this specific resource.

4.  **Bypass Technique**:
    *   To bypass the string matching filter (which likely checks for the exact admin UUID string), I URL-encoded the first character of the Admin's UUID.
    *   The character `9` becomes `%39`.
    *   The new payload was: `%390c3507d-09bb-43cb-8a2c-a5d3a72b06cc`.

5.  **Result**:
    *   Sending the request to `http://34.14.220.175:4000/viewProfile/uuid/%390c3507d-09bb-43cb-8a2c-a5d3a72b06cc` bypassed the filter.
    *   The server decoded the URL, processed the valid UUID, and returned the admin's profile JSON containing the flag.

## Flag
`ShaZ{403_1DOR_Byp4a33d_suc33sfully_XDXD!}`
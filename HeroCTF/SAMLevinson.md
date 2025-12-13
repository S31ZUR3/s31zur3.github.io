web

**Challenge:** Obtain the flag from a Sam Levinson fan club website where the login page is reportedly not working. A functional account on the IDP is provided: `user:oyJPNYd3HgeBkaE%!rP#dZvqf2z*4$^qcCW4V6WM`.

**Challenge URLs:**
- APP (Service Provider - SP): `http://web.heroctf.fr:8080`
- IDP (Identity Provider): `http://web.heroctf.fr:8081`

**Initial Analysis:**
1.  The challenge explicitly mentions "SAML", suggesting a vulnerability related to Security Assertion Markup Language.
2.  A Python script `decode.py` was present in the directory, hinting at SAML response manipulation (specifically, changing roles and stripping signatures).
3.  The provided credentials are for the IDP.
4.  The APP has a "SSO Login" link, which initiates the SAML flow.

**Reconnaissance (using `curl`):**

1.  **Visiting the APP:**
    `curl -v http://web.heroctf.fr:8080`
    This revealed a login page with a local login form and an "SSO Login" link to `/flag`.

2.  **Initiating SSO Login:**
    `curl -v -L http://web.heroctf.fr:8080/flag`
    This showed a `302 Found` redirect to `http://web.heroctf.fr:8081/sso` with a `SAMLRequest` parameter. The response also contained an HTML form to the IDP's `/sso` endpoint, including `user`, `password`, `SAMLRequest` (as a hidden field), and `RelayState` (as a hidden field). A `Set-Cookie` header for `saml_...` was also
    observed for `/saml/acs` on the SP, which had a `Max-Age` of 90 seconds.

**Initial Exploitation Attempts & Debugging:**

The initial idea was to use the provided `decode.py` script, which involved:
1.  Capturing the SAMLResponse from the IDP after successful authentication.
2.  Modifying the `eduPersonAffiliation` attribute from "Users" to "Administrators".
3.  Removing the XML Digital Signature (`<ds:Signature>...</ds:Signature>`).
4.  Re-encoding and submitting the modified SAMLResponse to the SP's Assertion Consumer Service (ACS) endpoint (`http://web.heroctf.fr:8080/saml/acs`).

However, direct implementation of this "Signature Stripping" attack led to a `403 Forbidden` error from the SP. Debugging revealed:

1.  **Signature Stripping Failure:** Even with the `decode.py` script's signature removal (which was initially buggy due to a regex issue, later fixed), the SP returned `403 Forbidden`. This indicated that the SP likely enforced signature validation and would not accept an unsigned assertion.
2.  **Expired Session/SAML Response:** Initial manual `curl` attempts failed due to the `saml_...` cookie (for SP state tracking) expiring (90 seconds) or the SAML Assertion's `NotOnOrAfter` condition expiring due to delays between steps.

**Refined Strategy: Automated XML Signature Wrapping (XSW) Attack**

To overcome the signature enforcement and time sensitivity, an automated Python script (`solve.py`) was developed using `urllib` to quickly perform the steps. The core of the solution involved an **XML Signature Wrapping (XSW)** attack:

1.  **Confirming Valid Login:** First, `solve.py` was configured to perform a normal login (no SAML modifications). This resulted in a successful `200 OK` from the SP, displaying a "Hello, user" page with the message: "You are not part of the "Administrators" group. You do not have the necessary privileges to view the flag." This confirmed that the base login flow worked and that the goal was indeed privilege escalation.

2.  **Implementing XSW (Type #2):**
    The SP required a valid signature, but we also needed to inject an "Administrators" role. XSW allows keeping the valid signature while injecting malicious content. The strategy was:
    *   **Capture a fresh SAMLResponse:** The `solve.py` script programmatically initiated the SAML flow to get a fresh, valid SAMLResponse from the IDP.
    *   **Extract the original Assertion:** The `<saml:Assertion>...</saml:Assertion>` block (which contains the valid signature and the "Users" role) was extracted from the fresh SAMLResponse.
    *   **Create a forged Assertion (Evil Assertion):** A copy of the original Assertion was made. In this copy:
        *   Its `ID` attribute was changed to a new, unique value (e.g., `ID="evil-assertion"`) to prevent collisions.
        *   The `eduPersonAffiliation` value was changed from "Users" to "Administrators".
        *   The `<ds:Signature>...</ds:Signature>` block was removed from this *Evil Assertion* (as it would be invalid after modification).
    *   **Wrap the Response:** The original `samlp:Response` XML was modified by inserting the *Evil Assertion* immediately *after* the original, valid Assertion. This creates a structure like:
        ```xml
        <samlp:Response ...>
          <saml:Assertion ID="original-id">...</saml:Assertion>  <!-- Original, signed, "Users" -->
          <saml:Assertion ID="evil-assertion">...</saml:Assertion> <!-- Forged, unsigned, "Administrators" -->
        </samlp:Response>
        ```
    *   **Re-encode and Submit:** The entire modified `samlp:Response` (with both assertions) was Base64 encoded and URL-encoded, then submitted to the SP's ACS endpoint.

**Result:**

This XSW #2 approach (evil assertion appended after the valid one) resulted in a `200 OK` response from the SP. The returned HTML page displayed "Hello, user" but now showed a tag for "Admin" and contained the flag:

```
<div class="alert ok">Access granted. Here is your flag:</div>
<pre class="flag" id="flagBox">Hero{S4ML_3XPL01T_FR0M_CR3J4M}</pre>
```

The SP's parsing logic likely performed signature validation on the first (valid) assertion, but then processed (or merged attributes from) subsequent assertions, including our forged one with the "Administrators" role. The technical details section showed:
`eduPersonAffiliation` : `Users, Administrators`
This confirms that the attributes from both assertions were considered, successfully elevating privileges.

**Flag:**
`Hero{S4ML_3XPL01T_FR0M_CR3J4M}`
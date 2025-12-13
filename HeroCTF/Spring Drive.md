web
## Challenge Overview
The "Spring Drive" challenge is a Java Spring application consisting of a backend API and a database (PostgreSQL), cached by Redis, and protected by a ClamAV file scanner. The goal is to retrieve a flag located in the `/app/` directory.


## Vulnerabilities

The application suffers from two critical vulnerabilities that, when chained together, allow for Remote Code Execution (RCE).

### 1. Weak Password Reset Token (Admin Account Takeover)
The `ResetPasswordToken` class implements a weak hash function:
```java
@Override
public int hashCode() {
    return token.hashCode() + email.hashCode();
}
```
The application stores tokens in memory and validates them using `contains()`, which relies on `equals()`. The `equals()` implementation checks if the token prefix (UUID) matches and if the hash codes are identical. This allows for a "Meet-in-the-Middle" attack:
1.  An attacker requests a reset token for their own account, obtaining a valid `UUID`.
2.  The attacker forges a token for the Admin (ID 1) using this `UUID`.
3.  The attacker finds a "collision email" string such that `Hash(ForgedToken) + Hash(CollisionEmail) == Hash(RealToken) + Hash(RealEmail)`.
4.  Using this collision email and forged token, the attacker can successfully reset the Admin's password.

### 2. Redis Command Injection via HTTP Method Smuggling (RCE)
The `FileController` exposes an endpoint `/file/remote-upload` accessible only to administrators. It takes a URL and an HTTP Method as input and uses `OkHttp` to fetch the resource.
The `method` parameter is passed directly to the `OkHttp` request builder without sufficient validation:
```java
Request request = new Request.Builder()
        .url(remoteUrl)
        .method(method, null)
        .build();
```
This allows injecting arbitrary data into the request line. By targeting the internal Redis service (`http://localhost:6379/`) and injecting the `RPUSH` command via the HTTP method, an attacker can add malicious entries to the `clamav_queue`.

The `ClamAVService` consumes paths from this queue and executes them using `Runtime.exec` with insufficient sanitization:
```java
String command = String.format("clamscan --quiet '%s'", filePath);
ProcessBuilder processBuilder = new ProcessBuilder("/bin/sh", "-c", command);
```
This leads to Command Injection.

## Exploit Chain

1.  **Registration:** The attacker registers a user (`attacker1`) with a valid email (`attacker1@x.com`) and password (>=8 chars).
2.  **Token Retrieval:** The attacker requests a password reset and retrieves the token (including UUID and ID) from the `/auth/email` debug endpoint.
3.  **Hash Collision:** A script calculates a "collision email" (`alikg88e`) that generates the same hash sum as the legitimate token when combined with the forged Admin token structure (`UUID|1`).
4.  **Admin Takeover:** The attacker sends a `reset-password` request using the collision email and forged token, setting the Admin password to `admin123`.
5.  **Persistence:** The attacker logs in as Admin and uploads a placeholder file (`pwn.txt`) to generate a valid, writable file path (e.g., `/app/uploads/<UUID>`).
6.  **RCE Injection:** The attacker uses the `remote-upload` endpoint to inject a Redis command:
    ```
    RPUSH clamav_queue "'; cp /app/flag*.txt /app/uploads/<UUID>; echo '"
    ```
    This command is pushed to the Redis queue.
7.  **Execution:** The `ClamAVService` (running on a cron every 60s) pops the payload from the queue. The injected command executes `cp`, overwriting the placeholder file with the contents of the flag file.
8.  **Retrieval:** The attacker downloads the placeholder file, which now contains the flag.

[exploit_console.js](/home/s31zur3/Downloads/heroctf/spring_drive/exploit_console.js)

## Flag
`Hero{8be9845ab07c17c7f0c503feb0d91184}`

[[HeroCTF 2025]]

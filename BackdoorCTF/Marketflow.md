### Vulnerability Analysis

1.  **Insecure Deserialization:**
    *   The endpoint `/api/analytics/reports` accepts a JSON payload and processes it using `ObjectManager.deserialize`.
    *   This method allows instantiating any class registered in `CLASS_REGISTRY` with arbitrary constructor arguments.
    *   This is the entry point for the exploit chain.

2.  **Arbitrary File Write (Gadget Chain):**
    *   The `Scheduler` processes tasks and, for `ReportConfiguration` objects, can trigger `cache_service.prime(output_config)`.
    *   `CacheService.prime` calls `config.persistence.write(data)`.
    *   `PersistenceAdapter.write` (the persistence object) uses `os.path.join` with user-controlled input. If an absolute path or path traversal (e.g., `../`) is provided, it can write to unintended locations.
    *   This allows us to write arbitrary content to files in the writable directories (specifically `/var/tmp/sessionmaze/templates` via traversal).

3.  **SSRF (Trigger Mechanism):**
    *   The `Scheduler` only processes tasks when `/internal/cron/process` is called. This endpoint is restricted to `localhost`.
    *   The `/api/webhooks/forward` endpoint uses `WebhookForwarder` to make HTTP requests.
    *   Although there is a protection mechanism (`is_safe_url`), it can be bypassed using a domain that resolves to 127.0.0.1 (e.g., `localtest.me`). This allows us to trigger the cron job externally.

4.  **Local File Inclusion (LFI):**
    *   The `TemplateRenderer` has a "legacy" mode for files ending in `.tpl`.
    *   If a template contains `@config: /path/to/file`, the renderer reads that file and includes its content in the output HTML.
    *   By writing a malicious `.tpl` file (using the file write vulnerability) and then instructing the application to use it as a template, we can read `/flag.txt`.

### Exploit Summary

I created and executed an exploit script (`exploit.py`) that performed the following steps:
1.  **Register & Login:** Created a user to access the authenticated API.
2.  **Stage 1 (Write):** Scheduled a malicious task to write a file named `exploit.tpl` to `../templates/exploit.tpl` (which resolves to `/var/tmp/sessionmaze/templates/exploit.tpl`). The content included `@config: /flag.txt`.
3.  **Trigger:** Used the SSRF vulnerability to hit `http://localtest.me:5000/internal/cron/process`, forcing the scheduler to execute the write task.
4.  **Stage 2 (Read):** Scheduled a second task to generate a report using the `exploit.tpl` template.
5.  **Trigger:** Triggered the scheduler again.
6.  **Retrieve:** Downloaded the generated report. The flag was embedded in an HTML comment within the report.

### Flag

`flag{n3st3d_d3s3r1al1z4t10n_ssrf_ch41n_c0mpl3t3_0b53wrf}`
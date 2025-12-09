## Reconnaissance
1.  **Initial Probing**:
    *   Input `1` -> "User found!"
    *   Input `999999` -> "No user found"
    
2.  **Vulnerability Detection**:
    *   We suspected SQL Injection.
    *   Input `1 AND 1=1` -> "User found!" (True condition)
    *   Input `1 AND 1=2` -> "No user found" (False condition)
    *   This confirmed a **Boolean-based Blind SQL Injection** vulnerability. We can ask the database true/false questions and infer data based on the response.

## Database Enumeration
1.  **Identifying the Database**:
    *   Standard MySQL functions like `database()` and `version()` failed or were filtered.
    *   We tested for SQLite by querying the `sqlite_master` table.
    *   Payload: `1 AND (SELECT 1 FROM sqlite_master LIMIT 1) = 1` -> "User found!"
    *   This confirmed the database is **SQLite**.

2.  **Finding Tables**:
    *   We knew there was likely a `users` table.
    *   To find the flag, we searched for other tables. We checked for a second table in `sqlite_master`.
    *   We wrote a Python script using binary search to extract the name of the table that is NOT 'users'.
    *   Payload logic: `1 AND (SELECT SUBSTR(name, 1, 1) FROM sqlite_master WHERE type='table' AND name != 'users' LIMIT 1) > 'char'`
    *   The script revealed a table named: `secret_flags`.

3.  **Finding Columns**:
    *   We needed to know the column names in `secret_flags`.
    *   We extracted the `CREATE TABLE` SQL statement for the `secret_flags` table from `sqlite_master`.
    *   Payload logic: `1 AND (SELECT SUBSTR(sql, 1, 1) FROM sqlite_master WHERE type='table' AND name='secret_flags') > 'char'`
    *   The result was:
        ```sql
        CREATE TABLE secret_flags (
            id INTEGER PRIMARY KEY,
            flag TEXT NOT NULL
        )
        ```
    *   This confirmed the target column is `flag`.

## Exploitation
1.  **Extracting the Flag**:
    *   With the table `secret_flags` and column `flag` identified, we wrote a final Python script to extract the flag's content character by character.
    *   Payload logic: `1 AND (SELECT SUBSTR(flag, 1, 1) FROM secret_flags LIMIT 1) > 'char'`
    *   The script used binary search for efficiency.

## Result
The extraction script successfully recovered the flag:

**Flag**: `flag{bl1nd_but_n0t_l0st_1n_th3_d4rk}`
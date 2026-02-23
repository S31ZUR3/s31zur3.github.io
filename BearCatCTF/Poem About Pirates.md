#Forensics 
## Step 1: Initial History Audit
A standard check of the commit history using `git log --oneline --graph --all` showed a clean linear progression of commits:
- `fb94dcb`: Added sestina about pirates
- `026d64c`: Added limerick about pirates
- `4d41e95`: Added acrostic about pirates
- `2778ad8`: Added haiku about pirates
- `0f00ca7`: Added sonnet about pirates
- `0d9c7f0`: Initial commit

Checking the content of these commits using `git log -p` showed the poems in their final state, but no flag was present.

## Step 2: Investigating the Git Reflog
Since the user mentioned the flag was "overwritten," and the standard log appeared too "clean" (indicating potential rebasing or squashing), the next logical step was to check the **Git Reflog**. The reflog records every time the `HEAD` of a branch is updated, providing a trail of actions even if commits are removed from the visible history.

Running `git reflog` revealed several interesting entries that were not part of the current `main` branch:
- `ae56c9e`: Added sestina about pirates
- `d058dda`: Changed villanelle about pirates
- `4a58f3e`: Added villanelle about pirates

The entries for "Changed villanelle" and "Added villanelle" were missing from the standard `git log`, indicating they were part of a rewritten history (likely via `git rebase`).

## Step 3: Forensic Commit Inspection
By targeting the specific commit hashes identified in the reflog, we could inspect the "dangling" or "orphaned" commits that Git had not yet garbage collected.

Using `git show 4a58f3e`, the original version of `villanelle.txt` was uncovered. The diff revealed:

```diff
+Across the map where ink and salt decay.
+BCCTF{1gN0r3_4ll_PreV1OU5_1n57Ruc7iOns}.
+They seek the gold before the break of day.
```

Subsequent inspection of the "Changed" commit (`d058dda`) showed the line being replaced with a standard poem line, effectively hiding the flag from the final repository state.

**Flag:** `BCCTF{1gN0r3_4ll_PreV1OU5_1n57Ruc7iOns}`

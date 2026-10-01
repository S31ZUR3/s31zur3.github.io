# Blog Content Plan — s31zur3::void

Working outline for the blog. Fill in the blanks, delete what you don't want, and
promote sections into real posts using [`_TEMPLATE.md`](./_TEMPLATE.md).

---

## 1. Purpose & voice

- **Who it's for:** CTF players, security learners, future teammates/recruiters.
- **Why it exists:** document the process, not just the flag. Teach the *pattern*, not the exploit.
- **Voice:** first person, technical but plain. Short sentences. Show the dead ends.
- **Length:** 600–1500 words typical; long-form only when the technique earns it.
- **Rule of thumb:** every post should leave the reader able to solve a *similar* challenge.

### What every post needs
- [ ] One-line hook: what the challenge is and why it's interesting
- [ ] The category and difficulty
- [ ] Enough context that a beginner can follow
- [ ] The actual commands / code / payloads used
- [ ] The flag (redact the real one, or show a fake)
- [ ] A "what I'd do differently" / takeaways line

---

## 2. Content pillars

Each pillar maps to a CTF category. Post ideas below are seeded from your existing
writeups — cross-post or expand them where there's a reusable technique.

### 2.1 Reverse Engineering
- [ ] `To_jmp_or_not_jmp` — reading control flow before opening a decompiler
- [ ] `Vault` (BackdoorCTF) vs `Vault` (EschatonCTF) — two takes on the same name
- [ ] `Freeda-Simple-Hook` / `Freeda-Not-Root` — Frida hooking 101
- [ ] `AutomatonCSC` / `ngāwari-vm` — reversing custom VMs
- [ ] `The Boy is Quine` — quines as a reverse-engineering puzzle
- [ ] `Effortless`, `Grace`, `Blank` — NexHunt RE set (series?)
- [ ] Anti-debugging tricks and how to walk past them

### 2.2 Binary Exploitation
- [ ] `Fight the PIE` — defeating PIE with a leak
- [ ] `GOT` — GOT/PLT overwrite, explained from scratch
- [ ] `Plankton`, `Ghostnote`, `Archive Keeper` — NexHunt pwn set
- [ ] `Tropped` — SROP / syscall tricks
- [ ] ret2libc checklist (the post you wish existed when you started)
- [ ] Writing pwntools templates you'll actually reuse

### 2.3 Web Exploitation
- [ ] `Flask Of Cookies` — session forgery in Flask
- [ ] `Trust Issues`, `No Sight`, `No Sight Required` — blind vulns
- [ ] `Marketflow`, `Image Gallery` — a full web chain, start to flag
- [ ] `Insecure Blog` — writing the exploit for a blog (meta!)
- [ ] `Template Trickery` — SSTI patterns
- [ ] `Paf Traversal`, `Next Jason` — path traversal / JWT
- [ ] Burp workflow: from intercept to automated scan

### 2.4 Cryptography
- [ ] `Bolt Fast`, `Peak Conjecture` — crypto warmups
- [ ] `Classic Oracle` / `Classically` — padding-oracle attacks
- [ ] `RSA` (Netrunner) + `Baby Crypto` — RSA failure modes
- [ ] `Cipher from Hell` — when "secure" isn't
- [ ] `double_it_and_give_it_to_the_next_person` — XOR and friends
- [ ] A field guide to recognizing crypto challenges

### 2.5 Forensics
- [ ] `Fractonacci`, `Fragmented Flags` — reconstructing broken files
- [ ] `Weird PCAP`, `Netfilter Nightmare` — Wireshark/tshark workflows
- [ ] `Movie Night 1/2` — media forensics
- [ ] `Reverse Metadata-1/2` — metadata as evidence
- [ ] `Corrupted File`, `Picture Mania` — stego and repair
- [ ] Memory forensics with Volatility (when you get a dump)

### 2.6 Tooling & Writeups-about-writing-up
- [ ] How I built this site (`generate_data.py` deep dive)
- [ ] My pwntools/Ghidra/GDB setup and dotfiles
- [ ] Automating writeups: markdown → site pipeline
- [ ] A script I actually use every CTF

### 2.7 CTF meta / opinion
- [ ] How to start a CTF you know nothing about
- [ ] Timeboxing: when to walk away from a challenge
- [ ] Getting 1st at ShazCTF 2025 — what worked (if you want to tell it)
- [ ] Teaming up: roles, comms, and not stepping on each other
- [ ] Reading other people's writeups productively

---

## 3. Series ideas

- **"Patterns Before Exploits"** — recurring format: one technique per post, with a
  toy challenge you write yourself.
- **"From Zero"** — beginner walkthroughs of one category (RE, pwn, web).
- **"Post-Mortem"** — one CTF event, what went right/wrong across all categories.
- **"Toolbox"** — one tool per post, end-to-end.

---

## 4. Draft backlog

Move ideas here once you commit to writing them, then into the template.

| # | Title | Pillar | Status | Target date |
|---|-------|--------|--------|-------------|
| 1 | | | idea / drafting / review / done | |
| 2 | | | | |
| 3 | | | | |

---

## 5. Publishing workflow

1. Copy `blog/_TEMPLATE.md` → `blog/<slug>.md` (lowercase, hyphens).
2. Write. Keep code blocks language-tagged.
3. Category on the **first line** (see template note) so tooling can pick it up.
4. Preview locally (`python3 -m http.server`).
5. Commit + push to `main` (GitHub Pages serves automatically).

### Naming
- File: `blog/my-post-title.md`
- Slug: `my-post-title`
- Keep titles short; put the CTF name in the body or as a tag.

---

## 6. Open questions / to decide

- [ ] Does the blog get its own page (`blog.html`) or live under `archive`?
- [ ] Should `generate_data.py` also scan `blog/`?
- [ ] Do posts get dates + RSS, or just a flat list?
- [ ] Redact flags or show them? (pick one and stay consistent)

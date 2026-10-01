# s31zur3.github.io

Minimal anime.js site: `index.html` (landing) + `archive.html` (writeups) + `blog.html` (blog).

## Building data.js

Writeups live as markdown in `CTFName/` folders. Regenerate the data bundle:

```bash
python3 generate_data.py
```

## Blog

Posts live as markdown in `blog/posts/`. Regenerate the blog bundle:

```bash
python3 generate_blog.py
```

- Read posts at `/blog` (hash routes: `#post/<slug>`).
- Compose a post at `/write` — it previews live and exports a `.md` file.
  Drop that file in `blog/posts/`, run the command above, then commit.

## Deploy

Push to `main` → served on GitHub Pages (CNAME: s31zur3.xyz).
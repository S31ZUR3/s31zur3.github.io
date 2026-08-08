# s31zur3.github.io

Minimal anime.js site: `index.html` (landing) + `archive.html` (writeups).

## Building data.js

Writeups live as markdown in `CTFName/` folders. Regenerate the data bundle:

```bash
python3 generate_data.py
```

## Deploy

Push to `main` → served on GitHub Pages (CNAME: s31zur3.xyz).
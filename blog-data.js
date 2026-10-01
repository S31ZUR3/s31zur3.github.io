const blogPosts = [
    {
        "slug": "welcome-to-the-void",
        "title": "Welcome to the void",
        "date": "2026-10-01",
        "category": "Miscellaneous",
        "tags": [
            "meta",
            "blog"
        ],
        "difficulty": "Easy",
        "summary": "What this blog is for, and what to expect.",
        "readingTime": 1,
        "html": "<h2>Welcome to the void</h2>\n<p>This is the first post. It exists so the blog isn't empty, and to show the format every post follows.</p>\n<h3>What goes here</h3>\n<p>Notes from CTFs, techniques worth remembering, and the occasional tool dump. The goal is the <strong>pattern before the exploit</strong> \u2014 the transferable idea, not just the flag.</p>\n<ul>\n<li>Reverse engineering</li>\n<li>Binary exploitation</li>\n<li>Web, crypto, and forensics</li>\n<li>Tooling and CTF meta</li>\n</ul>\n<h3>The format</h3>\n<p>Every post starts with front matter (title, date, category, tags, summary), then plain markdown. Code blocks are language-tagged:</p>\n<pre><code class=\"bash\">\nfile ./chall\n\nchecksec --file=./chall\n\n</code></pre>\n<p>That's it. Delete this post once you've written your own, or keep it as a reference.</p>"
    }
];

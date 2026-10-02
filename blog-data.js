const blogPosts = [
    {
        "slug": "day-1",
        "title": "Day 1",
        "date": "2026-10-02",
        "category": "Reverse Engineering",
        "tags": [
            "series",
            "rev"
        ],
        "difficulty": "Easy",
        "summary": "An easy rev chall from HTB",
        "readingTime": 1,
        "html": "<h2>Simple Encryptor</h2>\n<p>This challenge is a simple rev chall that takes in an flag and performs some operations on it and outputs an encrypted flag.</p>\n<p>Below is the decompilation of the encryption part:</p>\n<pre><code class=\"C\">\nfor (i = 0; i &lt; max; i = i + 1) {\n\n    temp = rand();\n\n    *(b + i) = *(b + i) ^ temp;\n\n    a = rand();\n\n    a = a &amp; 7;\n\n    *(b + i) = *(b + i) &lt;&lt; a | *(b + i) &gt;&gt; 8 - a;\n\n}\n\n</code></pre>\n<p>What this does is it <strong>XOR's</strong> the array with the random number generated from *rand()*. Then another variable is also initialized to get the value from *rand()*. Then this variable goes tthrough a bitwise <code>&amp;</code> operation with 7. After this the array goes through right shift operation and left shift operation.</p>\n<p>Reversing this encryption is simple.</p>\n<pre><code class=\"C\">\nfor (long i = 0; i &lt; max; i++) {\n\n        int temp = rand();\n\n        int a = rand();\n\n        a = a &amp; 7;\n\n        *(b + i) = (*(b + i) &gt;&gt; a) | (*(b + i) &lt;&lt; (8 - a));\n\n        *(b + i) = *(b + i) ^ temp;\n\n}\n\n</code></pre>\n<p>We just write the same for loop and the only changes we are making here are just this one line <code>*(b + i) = *(b + i) &lt;&lt; a | *(b + i) &gt;&gt; 8 - a;</code> to <code>*(b + i) = (*(b + i) &gt;&gt; a) | (*(b + i) &lt;&lt; (8 - a));</code>.</p>\n<p>I feel like I still got it in me :)))).</p>"
    },
    {
        "slug": "a-new-series",
        "title": "A new series",
        "date": "2026-10-01",
        "category": "Miscellaneous",
        "tags": [
            "series",
            "relearning"
        ],
        "difficulty": "",
        "summary": "Starting a series to relearn CTFs without leaning on AI \u2014 simple challenges first, then harder, one writeup at a time.",
        "readingTime": 2,
        "html": "<h2>A new series</h2>\n<p>After playing all these CTFs I realized I have spent more time on <strong>prompting</strong> than actually solving. This doesn't mean that I do not know how to solve. It's just that CTFs aren't what they used to be. After the release of all these <strong>CLI</strong> tools, CTFs just became who has the higher budget or who can prompt better. My dependancy on AI has also affected me while playing CTFs. So this is just a series that will help me depend less on AI. ;)))</p>\n<p>I will be starting by doing simple challenges to see if I still have it in me :))... As the days go on, I will be posting what I learn on that day and I will also be increasing the difficulty of the challenges. This way I can be better than the AI :)))))</p>\n<h3>Why bother</h3>\n<p>A flag you get from a prompt doesn't stick. The things I actually remember are the ones I sat with, got stuck on, and eventually broke. That is the whole point of this series: rebuild the muscle, not the answer sheet.</p>\n<h3>The rules</h3>\n<ul>\n<li>No AI while the timer is running. Docs, man pages and my own notes are fair game.</li>\n<li>Timebox every challenge. If I am stuck past the limit, I write down *why* and move on.</li>\n<li>Each post ends with what actually taught me something, not just the flag.</li>\n<li>Difficulty only goes up once the previous level feels boring.</li>\n</ul>\n<h3>What I'll cover</h3>\n<ol>\n<li><strong>Reverse engineering</strong> \u2014 reading disassembly by hand again.</li>\n<li><strong>Binary exploitation</strong> \u2014 the classic stack, then modern mitigations.</li>\n</ol>\n<h3>What each post will have</h3>\n<ul>\n<li>the challenge and what it hands me</li>\n<li>what I tried first, including the dead ends</li>\n<li>the actual solution</li>\n<li>the one thing worth remembering</li>\n</ul>\n<p>That's it. First writeup coming soon.</p>"
    }
];

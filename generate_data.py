import os
import json
import re

MANUAL_CATEGORIES = {
    'bolt fast': 'Cryptography',
    'ambystoma mexicanum': 'Cryptography',
    'peak conjecture': 'Cryptography',
    'the job': 'Cryptography',
    'fractonacci': 'Forensics',
    'where code': 'Reverse Engineering',
    'to_jmp_or_not_jmp': 'Reverse Engineering',
    'vault': 'Reverse Engineering',
    'flask of cookies': 'Web Exploitation',
    'image gallery': 'Web Exploitation',
    'trust issues': 'Web Exploitation',
    'marketflow': 'Web Exploitation',
    'no sight': 'Web Exploitation',
    'no sight required': 'Web Exploitation'
}

def parse_markdown(text):
    html = text
    
    # 1. Escape HTML first (except where we want to keep structure)
    # Actually, for simple MD, we usually trust the input or escape only specific parts.
    # But since we are generating HTML, we should be careful. 
    # Let's simple-replace key headers and blocks.
    
    # Headers
    html = re.sub(r'^### (.*)$', r'<h4>\1</h4>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.*)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^# (.*)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    
    # Code blocks (handle indentation and newlines)
    def code_block_repl(match):
        lang = match.group(1) if match.group(1) else ''
        code = match.group(2)
        # escape HTML in code
        code = code.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        return f'<pre><code class="{lang}">{code}</code></pre>'
    
    # Use non-greedy match including newlines
    html = re.sub(r'```(\w*)\n(.*?)```', code_block_repl, html, flags=re.DOTALL)
    
    # Inline code
    html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
    
    # Images: ![alt](src) -> <img src="src" alt="alt">
    html = re.sub(r'!\s*\[(.*?)\]\((.*?)\)', r'<img src="\2" alt="\1" style="max-width:100%;">', html)
    
    # Links: [text](url) -> <a href="url">text</a>
    html = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2" target="_blank">\1</a>', html)

    # Bold
    html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
    
    # Lists
    lines = html.split('\n')
    new_lines = []
    in_list = False
    for line in lines:
        if line.strip().startswith('- ') or line.strip().startswith('* '):
            if not in_list:
                new_lines.append('<ul>')
                in_list = True
            content = line.strip()[2:]
            new_lines.append(f'<li>{content}</li>')
        elif in_list:
            # If empty line or not a list item, close list
            if not line.strip():
                pass # ignore empty lines inside list context mostly, or close?
                     # Standard MD: empty line breaks list? 
                     # Let's assume non-list line breaks list
            else:
                 new_lines.append('</ul>')
                 in_list = False
                 new_lines.append(line)
        else:
            new_lines.append(line)
    if in_list:
        new_lines.append('</ul>')
        
    html = '\n'.join(new_lines)
    
    # Paragraphs
    # Split by double newlines to form paragraphs, but ignore block elements
    blocks = re.split(r'\n\s*\n', html)
    final_html = ""
    for block in blocks:
        block = block.strip()
        if not block: continue
        
        # Check if block is already wrapped or is a header/pre/ul
        if re.match(r'<(h\d|ul|pre|div|table)', block):
            final_html += block + "\n"
        else:
            # Preserve single line breaks within paragraphs as <br>
            # block_with_br = block.replace('\n', '<br>')
            # final_html += f'<p>{block_with_br}</p>\n'
            # Actually, standard MD ignores single newlines. But for writeups, people often like them preserved.
            # Let's strictly follow "Paragraphs are separated by empty lines".
            final_html += f'<p>{block}</p>\n'
            
    return final_html

def infer_category_tags(title, text):
    title_lower = title.lower()
    
    # Check Manual Overrides first (exact match or partial)
    for key, val in MANUAL_CATEGORIES.items():
        if key in title_lower:
             # We still want tags, so we'll infer them, but return the manual category
             _, tags = get_inferred_data(text)
             # Add the category name to tags if not present
             cat_slug = val.split(' ')[0].lower()
             if cat_slug not in tags: tags.append(cat_slug)
             return val, tags

    return get_inferred_data(text)

def get_inferred_data(text):
    text_lower = text.lower()
    categories = {
        'Cryptography': ['crypto', 'aes', 'rsa', 'cipher', 'xor', 'encoding'],
        'Web Exploitation': ['web', 'http', 'flask', 'cookie', 'xss', 'sql', 'injection', 'csrf', 'jwt'],
        'Binary Exploitation': ['pwn', 'buffer', 'overflow', 'shellcode', 'rop', 'ret2libc', 'heap', 'stack'],
        'Reverse Engineering': ['reverse', 'assembly', 'ghidra', 'disassembler', 'binary analysis', 'patch', 'crack'],
        'Forensics': ['forensics', 'pcap', 'wireshark', 'steg', 'image', 'disk', 'memory', 'shark'],
        'Misc': ['misc', 'sanity']
    }
    
    found_tags = []
    best_category = 'Miscellaneous'
    max_score = 0
    
    for cat, keywords in categories.items():
        score = 0
        for kw in keywords:
            if kw in text_lower:
                score += 1
                if kw not in found_tags:
                    found_tags.append(kw)
        
        if score > max_score:
            max_score = score
            best_category = cat
            
    return best_category, found_tags

def main():
    data = {
        "VUWCTF 2025": {"rank": "26th place", "description": "University-level competition with emphasis on practical security challenges.", "challenges": []},
        "Null CTF 2025": {"rank": "62nd place", "description": "Community-driven CTF with focus on real-world security scenarios.", "challenges": []},
        "MetaRed CTF 2025": {"rank": "66th place", "description": "Specialized competition focusing on red team operations and offensive security techniques.", "challenges": []},
        "BackdoorCTF 2025": {"rank": "79th place", "description": "Advanced competition featuring challenging pwn and reverse engineering problems.", "challenges": []},
        "HeroCTF v7": {"rank": "111th place", "description": "Competed in various challenge categories including web exploitation, cryptography, and reverse engineering.", "challenges": []},
        "PatriotCTF 2025": {"rank": "398th place", "description": "Comprehensive CTF with diverse challenge categories.", "challenges": []}
    }
    
    backdoor_dir = "BackdoorCTF"
    if os.path.exists(backdoor_dir):
        # Sort files to ensure stable order
        files = sorted([f for f in os.listdir(backdoor_dir) if f.endswith(".md")])
        for filename in files:
            filepath = os.path.join(backdoor_dir, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            title = filename.replace('.md', '')
            html_content = parse_markdown(content)
            
            # Pass title to help with manual override
            category, tags = infer_category_tags(title, content)
            
            # Append to BackdoorCTF 2025
            data["BackdoorCTF 2025"]["challenges"].append({
                "id": title.lower().replace(' ', '-'),
                "title": title,
                "category": category,
                "tags": tags,
                "writeup": html_content
            })

    # Output to data.js
    js_content = f"const ctfData = {json.dumps(data, indent=4)};"
    with open('data.js', 'w', encoding='utf-8') as f:
        f.write(js_content)
    print("data.js generated.")

if __name__ == "__main__":
    main()
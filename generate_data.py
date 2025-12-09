import os
import json
import re

def parse_markdown(text):
    html = text
    # Escape HTML special characters mostly handled by browser assignment but good to be safe if strictly parsing
    # But here we want to preserve structure.
    
    # Headers
    html = re.sub(r'^### (.*)$', r'<h4>\1</h4>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.*)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^# (.*)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    
    # Code blocks
    # Simple handling for ```language ... ```
    def code_block_repl(match):
        lang = match.group(1) if match.group(1) else ''
        code = match.group(2)
        # escape HTML in code
        code = code.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        return f'<pre><code class="{lang}">{code}</code></pre>'
    
    html = re.sub(r'```(\w*)\n(.*?)```', code_block_repl, html, flags=re.DOTALL)
    
    # Inline code
    html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
    
    # Bold
    html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
    
    # Lists
    # This is a bit simplistic: turn lines starting with - into list items.
    # We need to wrap them in ul.
    lines = html.split('\n')
    new_lines = []
    in_list = False
    for line in lines:
        if line.strip().startswith('- '):
            if not in_list:
                new_lines.append('<ul>')
                in_list = True
            content = line.strip()[2:]
            new_lines.append(f'<li>{content}</li>')
        else:
            if in_list:
                new_lines.append('</ul>')
                in_list = False
            new_lines.append(line)
    if in_list:
        new_lines.append('</ul>')
        
    html = '\n'.join(new_lines)
    
    # Paragraphs (simple: double newline is new paragraph)
    # But we already have headers and lists, so we need to be careful not to wrap those.
    # For simplicity in this MVP, we might rely on CSS whitespace or just wrap text blocks.
    # Let's just convert single newlines to <br> if not in pre? No, that breaks lists.
    # Let's leave layout mostly to CSS 'white-space: pre-wrap' or similar for the body text if possible,
    # OR replace \n\n with <p>...
    
    # Better approach for simple MD: split by double newlines, wrap in <p> if not starting with <h/ul/pre
    blocks = html.split('\n\n')
    final_html = ""
    for block in blocks:
        block = block.strip()
        if not block: continue
        if block.startswith('<h') or block.startswith('<ul') or block.startswith('<pre'):
            final_html += block + "\n"
        else:
            final_html += f'<p>{block}</p>\n'
            
    return final_html

def infer_category_tags(text):
    text_lower = text.lower()
    categories = {
        'Cryptography': ['crypto', 'aes', 'rsa', 'cipher', 'xor', 'encoding'],
        'Web Exploitation': ['web', 'http', 'flask', 'cookie', 'xss', 'sql', 'injection', 'csrf'],
        'Binary Exploitation': ['pwn', 'buffer', 'overflow', 'shellcode', 'rop', 'ret2libc', 'heap', 'stack'],
        'Reverse Engineering': ['reverse', 'assembly', 'ghidra', 'disassembler', 'binary analysis', 'patch'],
        'Forensics': ['forensics', 'pcap', 'wireshark', 'steg', 'image', 'disk', 'memory'],
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
        for filename in os.listdir(backdoor_dir):
            if filename.endswith(".md"):
                filepath = os.path.join(backdoor_dir, filename)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                title = filename.replace('.md', '')
                html_content = parse_markdown(content)
                category, tags = infer_category_tags(content)
                
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

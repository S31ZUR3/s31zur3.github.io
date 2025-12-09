import os
import json
import re

# Mapping folder names to Data Keys in the JSON
FOLDER_MAP = {
    "BackdoorCTF": "BackdoorCTF 2025",
    "PatriotCTF": "PatriotCTF 2025",
    "VuwCTF": "VUWCTF 2025"
}

# Fallback for manual overrides if first line is missing/empty
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
    
    # Headers
    html = re.sub(r'^### (.*)$', r'<h4>\1</h4>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.*)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^# (.*)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    
    # Code blocks
    def code_block_repl(match):
        lang = match.group(1) if match.group(1) else ''
        code = match.group(2)
        code = code.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        return f'<pre><code class="{lang}">{code}</code></pre>'
    
    html = re.sub(r'```(\w*)\n(.*?)```', code_block_repl, html, flags=re.DOTALL)
    
    # Inline code
    html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
    
    # Images
    html = re.sub(r'!\s*\[(.*?)\]\((.*?)\)', r'<img src="\2" alt="\1" style="max-width:100%;">', html)
    
    # Links
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
            if not line.strip():
                pass
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
    blocks = re.split(r'\n\s*\n', html)
    final_html = ""
    for block in blocks:
        block = block.strip()
        if not block: continue
        
        if re.match(r'<(h\d|ul|pre|div|table)', block):
            final_html += block + "\n"
        else:
            final_html += f'<p>{block}</p>\n'
            
    return final_html

def get_inferred_tags(text):
    text_lower = text.lower()
    categories = {
        'crypto': ['crypto', 'aes', 'rsa', 'cipher', 'xor', 'encoding'],
        'web': ['web', 'http', 'flask', 'cookie', 'xss', 'sql', 'injection', 'csrf', 'jwt'],
        'pwn': ['pwn', 'buffer', 'overflow', 'shellcode', 'rop', 'ret2libc', 'heap', 'stack'],
        'rev': ['reverse', 'assembly', 'ghidra', 'disassembler', 'binary analysis', 'patch', 'crack'],
        'forensics': ['forensics', 'pcap', 'wireshark', 'steg', 'image', 'disk', 'memory', 'shark'],
        'misc': ['misc', 'sanity']
    }
    
    found_tags = []
    for cat, keywords in categories.items():
        for kw in keywords:
            if kw in text_lower:
                if kw not in found_tags:
                    found_tags.append(kw)
    return found_tags

def clean_category(line):
    # Normalize category line (remove #, whitespace, make proper case)
    cat = line.strip().lower().replace('#', '')
    
    # Map common short codes to full names
    mapping = {
        'crypto': 'Cryptography',
        'cryptography': 'Cryptography',
        'web': 'Web Exploitation',
        'web exploitation': 'Web Exploitation',
        'pwn': 'Binary Exploitation',
        'binary exploitation': 'Binary Exploitation',
        'rev': 'Reverse Engineering',
        'reverse engineering': 'Reverse Engineering',
        'reverse': 'Reverse Engineering',
        'forensics': 'Forensics',
        'misc': 'Miscellaneous',
        'miscellaneous': 'Miscellaneous',
        'osint': 'OSINT'
    }
    return mapping.get(cat, cat.title())

def main():
    # Initialize data with descriptions and ranks
    # Ideally this metadata should be separate or read from a config, but hardcoding for MVP is fine.
    data = {
        "VUWCTF 2025": {"rank": "26th place", "description": "University-level competition with emphasis on practical security challenges.", "challenges": []},
        "Null CTF 2025": {"rank": "62nd place", "description": "Community-driven CTF with focus on real-world security scenarios.", "challenges": []},
        "MetaRed CTF 2025": {"rank": "66th place", "description": "Specialized competition focusing on red team operations and offensive security techniques.", "challenges": []},
        "BackdoorCTF 2025": {"rank": "79th place", "description": "Advanced competition featuring challenging pwn and reverse engineering problems.", "challenges": []},
        "HeroCTF v7": {"rank": "111th place", "description": "Competed in various challenge categories including web exploitation, cryptography, and reverse engineering.", "challenges": []},
        "PatriotCTF 2025": {"rank": "398th place", "description": "Comprehensive CTF with diverse challenge categories.", "challenges": []}
    }
    
    # Iterate through folders
    for folder_name, ctf_key in FOLDER_MAP.items():
        if os.path.exists(folder_name) and ctf_key in data:
            files = sorted([f for f in os.listdir(folder_name) if f.endswith(".md")])
            for filename in files:
                filepath = os.path.join(folder_name, filename)
                
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                if not lines: continue

                # Check first line for category
                first_line = lines[0].strip()
                content_lines = lines # Default to all lines
                category = "Miscellaneous" # Default
                
                # Heuristic: If first line is short and looks like a category, use it and pop it
                if len(first_line) < 30 and first_line.lower() in ['crypto', 'cryptography', 'web', 'pwn', 'rev', 'reverse', 'forensics', 'misc', 'osint', 'network']:
                     category = clean_category(first_line)
                     content_lines = lines[1:] # Skip first line
                else:
                    # Fallback to manual map or title inference
                    title_lower = filename.replace('.md', '').lower()
                    for k, v in MANUAL_CATEGORIES.items():
                        if k in title_lower:
                            category = v
                            break

                # Join content back
                content = "".join(content_lines)
                
                title = filename.replace('.md', '')
                html_content = parse_markdown(content)
                tags = get_inferred_tags(content)
                
                data[ctf_key]["challenges"].append({
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

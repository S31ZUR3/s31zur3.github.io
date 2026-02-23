import os
import json
import re

# Mapping folder names to Data Keys in the JSON
FOLDER_MAP = {
    "BackdoorCTF": "BackdoorCTF 2025",
    "PatriotCTF": "PatriotCTF 2025",
    "VuwCTF": "VUWCTF 2025",
    "MetaRed CTF": "MetaRed CTF 2025",
    "NullCTF": "Null CTF 2025",
    "HeroCTF": "HeroCTF v7",
    "NexHuntCTF": "NexHuntCTF 2025",
    "ShazCTF": "ShazCTF 2025",
    "EschatonCTF": "EschatonCTF 2026",
    "BearCatCTF": "BearCatCTF 2026"
}

# Fallback for manual overrides
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
    'no sight required': 'Web Exploitation',
    # NexHuntCTF overrides
    'the scribe': 'Miscellaneous',
    'plankton': 'Binary Exploitation',
    'classic oracle': 'Cryptography',
    'web daveloper': 'Web Exploitation',
    'effortless': 'Reverse Engineering',
    'grace': 'Reverse Engineering',
    'tarnished': 'Reverse Engineering',
    'ghostnote': 'Binary Exploitation',
    'archive keeper': 'Binary Exploitation',
    'blank': 'Reverse Engineering',
    'blinders': 'Beginner', 
    'allo': 'Miscellaneous',
    'huntme3': 'Reverse Engineering',
    'silent flag': 'Blockchain',
    'chain clue': 'Blockchain',
    'calculator': 'Web Exploitation',
    'can you hear the music?': 'Beginner', 
    'huntme2': 'Beginner', 
    'huntme1': 'Beginner' 
}

def escape_html(text):
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def process_inline_formatting(text):
    # Images: ![alt](src)
    # We replace images first so they don't get confused with links
    text = re.sub(r'!\[(.*?)\]\((.*?)\)', r'<img src="\2" alt="\1" style="max-width:100%;">', text)
    
    # Links: [text](url)
    # Simple regex for links
    text = re.sub(r'(?<!\!)\[(.*?)\]\((.*?)\)', r'<a href="\2" target="_blank">\1</a>', text)
    
    # Bold: **text**
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    
    # Inline Code: `text`
    text = re.sub(r'`([^`]+)`', lambda m: f'<code>{escape_html(m.group(1))}</code>', text)
    return text

def parse_markdown(text):
    lines = text.split('\n')
    html_output = []
    
    state = 'NORMAL' # NORMAL, CODE_BLOCK, UL_LIST, OL_LIST
    buffer = [] # To accumulate paragraph text
    
    def flush_buffer():
        if buffer:
            content = ' '.join(buffer).strip()
            if content:
                html_output.append(f'<p>{process_inline_formatting(content)}</p>')
            buffer.clear()

    for line in lines:
        stripped = line.strip()
        
        # --- CODE BLOCKS ---
        if line.startswith('```'):
            if state == 'CODE_BLOCK':
                # End of code block
                html_output.append(f'</code></pre>')
                state = 'NORMAL'
            else:
                # Start of code block
                flush_buffer()
                if state in ['UL_LIST', 'OL_LIST']:
                    html_output.append('</ul>' if state == 'UL_LIST' else '</ol>')
                    state = 'NORMAL'
                
                lang = stripped[3:].strip()
                html_output.append(f'<pre><code class="{lang}">')
                state = 'CODE_BLOCK'
            continue
            
        if state == 'CODE_BLOCK':
            # Verbatim code line
            html_output.append(escape_html(line) + '\n')
            continue

        # --- HEADERS ---
        if stripped.startswith('#'):
            flush_buffer()
            if state in ['UL_LIST', 'OL_LIST']:
                html_output.append('</ul>' if state == 'UL_LIST' else '</ol>')
                state = 'NORMAL'
                
            level = len(stripped.split(' ')[0])
            content = stripped[level:].strip()
            # Map standard MD headers to appropriate HTML levels (h2-h4)
            tag = f'h{min(level + 1, 6)}' 
            html_output.append(f'<{tag}>{process_inline_formatting(content)}</{tag}>')
            continue

        # --- UNORDERED LISTS ---
        if stripped.startswith('- ') or stripped.startswith('* '):
            flush_buffer()
            if state == 'OL_LIST':
                html_output.append('</ol>')
                state = 'NORMAL'
            if state != 'UL_LIST':
                html_output.append('<ul>')
                state = 'UL_LIST'
            
            content = stripped[2:].strip()
            html_output.append(f'<li>{process_inline_formatting(content)}</li>')
            continue

        # --- ORDERED LISTS ---
        # Match "1. ", "2. " etc.
        if re.match(r'^\d+\.\s', stripped):
            flush_buffer()
            if state == 'UL_LIST':
                html_output.append('</ul>')
                state = 'NORMAL'
            if state != 'OL_LIST':
                html_output.append('<ol>')
                state = 'OL_LIST'
            
            # Remove the number and dot
            content = re.sub(r'^\d+\.\s', '', stripped).strip()
            html_output.append(f'<li>{process_inline_formatting(content)}</li>')
            continue

        # --- EMPTY LINES / PARAGRAPH BREAKS ---
        if not stripped:
            flush_buffer()
            if state in ['UL_LIST', 'OL_LIST']:
                html_output.append('</ul>' if state == 'UL_LIST' else '</ol>')
                state = 'NORMAL'
            continue
            
        # --- NORMAL TEXT / PARAGRAPH ---
        if state in ['UL_LIST', 'OL_LIST']:
            # Assuming flat structure for now: close list.
            html_output.append('</ul>' if state == 'UL_LIST' else '</ol>')
            state = 'NORMAL'
        
        buffer.append(line)

    # Final cleanup
    flush_buffer()
    if state == 'CODE_BLOCK':
        html_output.append('</code></pre>')
    if state in ['UL_LIST', 'OL_LIST']:
        html_output.append('</ul>' if state == 'UL_LIST' else '</ol>')
        
    return '\n'.join(html_output)

def get_inferred_tags(text):
    text_lower = text.lower()
    categories = {
        'crypto': ['crypto', 'aes', 'rsa', 'cipher', 'xor', 'encoding'],
        'web': ['web', 'http', 'flask', 'cookie', 'xss', 'sql', 'injection', 'csrf', 'jwt'],
        'pwn': ['pwn', 'buffer', 'overflow', 'shellcode', 'rop', 'ret2libc', 'heap', 'stack'],
        'rev': ['reverse', 'assembly', 'ghidra', 'disassembler', 'binary analysis', 'patch', 'crack'],
        'forensics': ['forensics', 'pcap', 'wireshark', 'steg', 'image', 'disk', 'memory', 'shark'],
        'misc': ['misc', 'sanity'],
        'blockchain': ['blockchain', 'solidity', 'ethereum', 'smart contract']
    }
    
    found_tags = []
    for cat, keywords in categories.items():
        for kw in keywords:
            if kw in text_lower:
                if kw not in found_tags:
                    found_tags.append(kw)
    return found_tags

def clean_category(line):
    cat = line.strip().lower().replace('#', '')
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
        'osint': 'OSINT',
        'blockchain': 'Blockchain',
        'android': 'Mobile',
        'mobile': 'Mobile'
    }
    return mapping.get(cat, cat.title())

def main():
    data = {
        "BearCatCTF 2026": {"rank": "136th place", "description": "Engaging competition with a variety of interesting challenges in cryptography, pwn, and reverse engineering.", "challenges": []},
        "EschatonCTF 2026": {"rank": "23rd place", "description": "Solved various challenges across multiple categories.", "challenges": []},
        "ShazCTF 2025": {"rank": "1st place", "description": "Achieved 1st place globally. Featured a mix of challenging security problems across all categories.", "challenges": []},
        "VUWCTF 2025": {"rank": "26th place", "description": "University-level competition with emphasis on practical security challenges.", "challenges": []},
        "Null CTF 2025": {"rank": "62nd place", "description": "Community-driven CTF with focus on real-world security scenarios.", "challenges": []},
        "MetaRed CTF 2025": {"rank": "66th place", "description": "Specialized competition focusing on red team operations and offensive security techniques.", "challenges": []},
        "BackdoorCTF 2025": {"rank": "79th place", "description": "Advanced competition featuring challenging pwn and reverse engineering problems.", "challenges": []},
        "HeroCTF v7": {"rank": "111th place", "description": "Competed in various challenge categories including web exploitation, cryptography, and reverse engineering.", "challenges": []},
        "PatriotCTF 2025": {"rank": "398th place", "description": "Comprehensive CTF with diverse challenge categories.", "challenges": []},
        "NexHuntCTF 2025": {"rank": "31st place", "description": "Latest competition writeups.", "challenges": []} 
    }
    
    for folder_name, ctf_key in FOLDER_MAP.items():
        print(f"Processing folder: {folder_name} for key: {ctf_key}")
        if os.path.exists(folder_name) and ctf_key in data:
            files = sorted([f for f in os.listdir(folder_name) if f.endswith(".md")])
            print(f"Found {len(files)} markdown files in {folder_name}")
            for filename in files:
                print(f"  Processing file: {filename}")
                filepath = os.path.join(folder_name, filename)
                
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                if not lines: continue

                first_line = lines[0].strip()
                content_lines = lines 
                category = "Miscellaneous"
                
                content = "".join(content_lines)
                title = filename.replace('.md', '')

                # 1. First check for MANUAL OVERRIDE (highest priority)
                manual_category_found = False
                title_lower = filename.replace('.md', '').lower()
                
                # Check for direct filename match in MANUAL_CATEGORIES
                if title_lower in MANUAL_CATEGORIES:
                    category = MANUAL_CATEGORIES[title_lower]
                    manual_category_found = True
                    print(f"    [OVERRIDE] Applied manual category '{category}' for '{title}'")
                else:
                    # Fallback to manual map using 'in' operator for partial matches
                    for k, v in MANUAL_CATEGORIES.items():
                        if k in title_lower:
                            category = v
                            manual_category_found = True
                            print(f"    [OVERRIDE-PARTIAL] Applied manual category '{category}' for '{title}'")
                            break
                
                # 2. If no manual override, try to infer from first line
                if not manual_category_found:
                    check_val = first_line.strip().lower().lstrip('#').strip()
                    if len(first_line) < 30 and check_val in ['crypto', 'cryptography', 'web', 'web exploitation', 'pwn', 'binary exploitation', 'rev', 'reverse', 'reverse engineering', 'forensics', 'misc', 'miscellaneous', 'osint', 'network', 'beginner', 'blockchain', 'android', 'mobile']:
                         category = clean_category(first_line)
                         content_lines = lines[1:]
                         content = "".join(content_lines)
                    else:
                        # 3. If still nothing, it stays as default "Miscellaneous" (or you could add content-based inference here)
                        pass

                html_content = parse_markdown(content)
                tags = get_inferred_tags(content)
                
                data[ctf_key]["challenges"].append({
                    "id": title.lower().replace(' ', '-').replace('?', '').replace('.', ''), # Clean ID for special chars
                    "title": title,
                    "category": category,
                    "tags": tags,
                    "writeup": html_content
                })

    js_content = f"const ctfData = {json.dumps(data, indent=4)};"
    with open('data.js', 'w', encoding='utf-8') as f:
        f.write(js_content)
    print("data.js generated.")

if __name__ == "__main__":
    main()

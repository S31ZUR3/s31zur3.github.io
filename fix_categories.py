import os

DIR = "NexHuntCTF"

CATEGORIES = {
    'Forensics': ['pcap', 'wireshark', 'network', 'forensics', 'shark', 'capture'],
    'Reverse Engineering': ['binary', 'reverse', 'ghidra', 'ida', 'assembly', 'decompiler'],
    'Web Exploitation': ['web', 'http', 'xss', 'sql', 'injection', 'csrf', 'flask', 'jwt', 'cookie'],
    'Cryptography': ['crypto', 'xor', 'aes', 'rsa', 'cipher', 'encoding', 'decrypt'],
    'Binary Exploitation': ['pwn', 'buffer', 'overflow', 'shellcode', 'ret2libc', 'heap', 'stack'],
    'Miscellaneous': ['misc', 'sanity', 'jail']
}

def infer_category(text):
    text_lower = text.lower()
    scores = {cat: 0 for cat in CATEGORIES}
    for cat, keywords in CATEGORIES.items():
        for kw in keywords:
            if kw in text_lower:
                scores[cat] += 1
    
    # Prioritize specific matches
    if scores['Cryptography'] > 0 and 'crypto' in text_lower: return 'Cryptography'
    if scores['Web Exploitation'] > 0 and 'web' in text_lower: return 'Web Exploitation'
    
    best_cat = max(scores, key=scores.get)
    if scores[best_cat] == 0:
        return 'Miscellaneous'
    return best_cat

for filename in os.listdir(DIR):
    if not filename.endswith(".md"): continue
    
    filepath = os.path.join(DIR, filename)
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    if not lines: continue
    
    first_line = lines[0].strip().lower()
    
    # Check if already has category
    known_cats = ['crypto', 'cryptography', 'web', 'pwn', 'rev', 'reverse', 'forensics', 'misc', 'osint', 'network']
    if any(first_line.startswith(c) for c in known_cats) and len(first_line) < 20:
        print(f"Skipping {filename}, already has category: {first_line}")
        continue
        
    # Infer
    content = "".join(lines)
    category = infer_category(content)
    
    print(f"Updating {filename}: Inferred {category}")
    
    # Prepend
    with open(filepath, 'w') as f:
        f.write(f"{category}\n" + "".join(lines))

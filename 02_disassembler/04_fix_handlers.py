"""
Fix handler extraction - properly parse the Proxy array handlers.
The naive regex split breaks on inner function() literals.
Need to properly parse with brace/bracket matching.
"""

import re
import json

with open(r"E:\kasada fully reverse\work\vm_section.js", "r") as f:
    src = f.read()

# Find the Proxy array start
proxy_pos = src.find('u=new Proxy([')
array_start = src.index('[', proxy_pos)

# Properly find the matching ] with depth tracking
# But also handle the Proxy({get:...}) handler after the array
# The structure is: u=new Proxy([...], {...})

# Parse the array properly by tracking depth
depth = 0
i = array_start
while i < len(src):
    c = src[i]
    if c == '[': depth += 1
    elif c == ']': 
        depth -= 1
        if depth == 0:
            array_end = i
            break
    elif c == '"' or c == "'":
        # Skip string
        q = c
        i += 1
        while i < len(src) and src[i] != q:
            if src[i] == '\\': i += 1
            i += 1
    elif c == '/' and i + 1 < len(src):
        if src[i+1] == '/':
            while i < len(src) and src[i] != '\n': i += 1
        elif src[i+1] == '*':
            i += 2
            while i < len(src) - 1 and not (src[i] == '*' and src[i+1] == '/'):
                i += 1
            i += 1
    i += 1

array_content = src[array_start+1:array_end]
print(f"Proxy array content length: {len(array_content)}")

# Now split into handlers properly - each handler is "function(...){...}"
# Need to match balanced braces
handlers = []
i = 0
while i < len(array_content):
    # Skip whitespace and commas
    while i < len(array_content) and array_content[i] in ' ,\n\t\r':
        i += 1
    if i >= len(array_content):
        break
    
    # Should start with "function"
    if not array_content[i:].startswith('function'):
        # Might be end of array or something unexpected
        print(f"  Unexpected at pos {i}: '{array_content[i:i+30]}'")
        break
    
    # Find the opening brace of the function body
    brace_start = array_content.index('{', i)
    
    # Match balanced braces
    depth = 0
    j = brace_start
    while j < len(array_content):
        c = array_content[j]
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                # End of function
                handler = array_content[i:j+1]
                handlers.append(handler)
                i = j + 1
                break
        elif c == '"' or c == "'":
            q = c
            j += 1
            while j < len(array_content) and array_content[j] != q:
                if array_content[j] == '\\': j += 1
                j += 1
        elif c == '`':
            j += 1
            while j < len(array_content) and array_content[j] != '`':
                if array_content[j] == '\\': j += 1
                j += 1
        elif c == '/' and j + 1 < len(array_content):
            if array_content[j+1] == '/':
                while j < len(array_content) and array_content[j] != '\n': j += 1
            elif array_content[j+1] == '*':
                j += 2
                while j < len(array_content) - 1:
                    if array_content[j] == '*' and array_content[j+1] == '/':
                        j += 1
                        break
                    j += 1
        j += 1
    else:
        print(f"  Unmatched braces at handler {len(handlers)}")
        break

print(f"Extracted {len(handlers)} handlers")
print()

# Now analyze each handler correctly
print("=" * 80)
print("CORRECT HANDLER ANALYSIS")
print("=" * 80)
print()

for idx, h in enumerate(handlers):
    # Count operand consumption
    e_count = len(re.findall(r'\be\s*\(\s*n\s*\)', h))
    v_count = len(re.findall(r'\bv\s*\(\s*n\s*\)', h))
    a_calls = len(re.findall(r'\ba\s*\(\s*n\s*,', h))
    
    # Pop function - r[5] assignment then o(n) calls
    has_pop_var = bool(re.search(r'=\s*r\[5\]', h))
    pop_calls = 0
    if has_pop_var:
        pop_calls = len(re.findall(r'\bo\s*\(\s*n\s*\)', h))
    
    has_store = a_calls > 0
    
    # Determine semantics from handler body
    sem = ""
    if '.s[' in h and not has_store:
        sem = "scope_write"
    elif has_store and '.s[' in h:
        sem = "scope_read"
    
    total_bc = e_count + pop_calls + (1 if has_store else 0)
    
    short = h[:80].replace('\n', ' ')
    print(f"  OP_{idx:2d}: e={e_count} pop={pop_calls} dest={'Y' if has_store else 'N'} total_bc={total_bc} | {short}")

# Save handlers to file for reference
with open(r"E:\kasada fully reverse\work\handlers.json", "w") as f:
    json.dump(handlers, f, indent=2)

print()
print("=" * 80)
print("DISPATCH LOOP ANALYSIS")
print("=" * 80)
print()

# The dispatch loop is after the Proxy definition
# Found: ,(function(){var e=Array.from({length:87},...) return{get:function(n,r){...return n[e[T]]}}})()
# This is the Proxy HANDLER (second arg to new Proxy)
# It has a permutation table: e = Array.from({length:87}, (n,r) => r)
# With get: function(n,r) { return n[e[Number(r)]] }
# So e is a permutation/mapping of opcode indices!

# Find the permutation table
perm_match = re.search(r'Array\.from\(\{length:\s*(\d+)\}', src[array_end:])
if perm_match:
    length = int(perm_match.group(1))
    print(f"Permutation table length: {length}")
    
    # The get handler: return n[e[T]] where T is the opcode
    # This means the bytecode opcode is REMAPPED through permutation e[]
    # e = Array.from({length:87}, (n,r) => r) = identity permutation [0,1,2,...86]
    # Wait - if it's just (n,r) => r, that's identity mapping!
    # BUT the source might have a more complex initializer
    
    # Let me get the full Array.from call
    after_array = src[array_end:]
    af_start = after_array.find('Array.from')
    af_context = after_array[af_start:af_start+300]
    print(f"Permutation code: {af_context[:200]}")
    print()
    
    # Check: if the permutation is identity, opcodes map directly to handler indices
    # Array.from({length:87}, function(n,r){return r}) = [0,1,2,...,86]
    # This IS identity. So opcode X maps to handler X.
    
    # BUT wait - the handler count is 89 but permutation is length 87!
    # This means only opcodes 0-86 are valid (87 entries)
    # But we found 89 handlers... some might be unused or special

print()
print("=" * 80)
print("UNDERSTANDING OP_56 (THE REAL ONE)")
print("=" * 80)
print()

# Now with correct parsing, handler 55 should include the full method_call logic
# and handler 56 should be the ACTUAL opcode 56 handler
if len(handlers) > 56:
    print(f"Handler 55 (first 200 chars):")
    print(f"  {handlers[55][:200]}")
    print()
    print(f"Handler 56 (first 200 chars):")
    print(f"  {handlers[56][:200]}")
    print()
    if len(handlers) > 57:
        print(f"Handler 57 (first 200 chars):")
        print(f"  {handlers[57][:200]}")
        print()

# Now let's find the ACTUAL dispatch loop
# It should be a while loop that:
# 1. Reads opcode from t[pc++]
# 2. Calls u[opcode](frame, G, F, s, n, r)

print("Looking for the dispatch loop...")
# Search for the pattern where handlers are called
# u[t[...]] or u.get pattern
dispatch_matches = list(re.finditer(r'u\s*\[\s*t\s*\[', src))
print(f"Found {len(dispatch_matches)} u[t[...]] patterns")
for m in dispatch_matches:
    ctx = src[max(0,m.start()-50):m.start()+200]
    print(f"  At pos {m.start()}: {ctx[:150]}")
    print()

# Alternative: look for the execution function with while loop
while_pos = src.find('while')
print(f"\nFirst while at pos {while_pos}")
while_ctx = src[while_pos:while_pos+500]
print(while_ctx[:300])

# Search more specifically
exec_match = re.search(r'while\s*\(\s*(\!0|true|1)\s*\)\s*\{[^}]*\bu\b', src)
if exec_match:
    print(f"\nDispatch while loop at pos {exec_match.start()}:")
    print(src[exec_match.start():exec_match.start()+300])

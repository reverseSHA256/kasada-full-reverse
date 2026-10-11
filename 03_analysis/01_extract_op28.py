"""
Extract and analyze the exact OP_28 handler from vm_section.js
to definitively determine if it's a READ or WRITE operation.
"""

import re

with open(r"E:\kasada fully reverse\work\vm_section.js", "r") as f:
    src = f.read()

# Find the Proxy array
proxy_pos = src.find('u=new Proxy([')
bracket_start = src.index('[', proxy_pos)

# Find matching ]
depth = 0
end = bracket_start
for i in range(bracket_start, len(src)):
    if src[i] == '[': depth += 1
    elif src[i] == ']': depth -= 1
    if depth == 0: end = i + 1; break

handler_src = src[bracket_start+1:end-1]

# Split into individual handlers
handlers = re.split(r',(?=function\()', handler_src)

print(f"Total handlers: {len(handlers)}")
print()

# Extract handler 28 (0-indexed)
if len(handlers) > 28:
    h28 = handlers[28]
    print("=" * 70)
    print("HANDLER 28 (OP_28) - Scope Chain Operation")
    print("=" * 70)
    print(h28)
    print()
    
    # Count operand reads
    e_count = len(re.findall(r'\be\s*\(\s*n\s*\)', h28))
    v_count = len(re.findall(r'\bv\s*\(\s*n\s*\)', h28))
    print(f"  e(n) calls (standard operand reads): {e_count}")
    print(f"  v(n) calls (scope variable reads): {v_count}")
    print(f"  Total arity: {e_count + v_count}")
    
    # Check if it calls a(n, ...) which is the store function
    a_calls = re.findall(r'\ba\s*\(\s*n\s*,', h28)
    print(f"  a(n, ...) calls (store to register): {len(a_calls)}")
    
    # Check for scope writes
    if '.s[' in h28:
        print("  Contains scope write (.s[...])")
    
    print()
    print("INTERPRETATION:")
    if len(a_calls) > 0:
        print("  OP_28 STORES a result to a register (it's a READ from scope)")
    else:
        if '.s[' in h28:
            print("  OP_28 does NOT store to register but writes to scope (it's a WRITE to scope)")
        else:
            print("  OP_28 semantics unclear")

print()
print("=" * 70)
print("Also checking OP_5, OP_10, OP_19, OP_57 for comparison")
print("=" * 70)

for idx in [5, 10, 19, 57]:
    if idx < len(handlers):
        h = handlers[idx]
        e_count = len(re.findall(r'\be\s*\(\s*n\s*\)', h))
        v_count = len(re.findall(r'\bv\s*\(\s*n\s*\)', h))
        a_calls = re.findall(r'\ba\s*\(\s*n\s*,', h)
        print(f"\nOP_{idx} (arity e={e_count}, v={v_count}, stores={len(a_calls)}):")
        print(f"  {h[:200]}")
        if '.s[' in h:
            print("  >>> Contains scope write")
        if len(a_calls) > 0:
            print("  >>> Stores result to register")

# Also let's look at the j function (pop/get top of stack)
# And understand how F works (the store function)
print()
print("=" * 70)
print("F (store function) definition:")
print("=" * 70)
f_match = re.search(r'function F\([^)]*\)\s*\{[^}]*\}', src)
if f_match:
    print(f_match.group())
    print()
    print("F(e, n) stores value n into register e.o[B(e)]")
    print("B(e) reads the next bytecode int and shifts right 5 = register index")
    print("So a(n, value) = F(n, value) = n.o[B(n)] = value")
    print("This writes to the register indicated by the NEXT bytecode element")

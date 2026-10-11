"""
Analyze OP_56 and the handler dispatch mechanism.
The key issue: OP_56 doesn't appear to be a normal opcode handler.
It's at the END of the Proxy array and looks different.

Also: re-examine the DATA entries after OP_56.
These might actually be consumed by the DISPATCH LOOP itself, not by handlers.

The dispatch loop reads:
1. The next opcode from bytecode
2. Calls the handler
3. But some control flow might be managed by the dispatcher BETWEEN handler calls

The pattern:
  OP_56
  DATA n  (large number like 787, 3939, etc)
  DATA m  (usually 128, 160, 192, etc)

The large numbers (787, 3939) could be:
- Frame/continuation pointers
- Scope slot references for the dispatcher
- Internal VM state words consumed by the dispatch loop
"""

import re
import json

# Load VM source to understand the dispatch loop
with open(r"E:\kasada fully reverse\work\vm_section.js", "r") as f:
    src = f.read()

# Find handler 56
proxy_pos = src.find('u=new Proxy([')
bracket_start = src.index('[', proxy_pos)
depth = 0
end = bracket_start
for i in range(bracket_start, len(src)):
    if src[i] == '[': depth += 1
    elif src[i] == ']': depth -= 1
    if depth == 0: end = i + 1; break

handler_src = src[bracket_start+1:end-1]
handlers = re.split(r',(?=function\()', handler_src)

print(f"Handler 56:")
print(f"  {handlers[56]}")
print()

# Now find the DISPATCH LOOP (function U or similar)
# The dispatch loop is the while(true) that reads opcodes and calls handlers
# Look for the pattern: while(1) or while(true) with u[opcode](...)

# Find all "while" patterns
while_matches = list(re.finditer(r'while\s*\(\s*(true|1|!0)\s*\)', src))
print(f"Found {len(while_matches)} while(true/1) loops")
for m in while_matches:
    ctx = src[m.start():m.start()+300]
    if 'u[' in ctx or 'u.get' in ctx or 't[' in ctx:
        print(f"\n  Dispatch loop candidate at pos {m.start()}:")
        print(f"  {ctx[:200]}")
        print()

# Look for the main execution function
# It typically reads opcodes from t[] array using n.o[0] as PC
exec_pattern = re.finditer(r'function\s+\w*\s*\([^)]*\)\s*\{[^}]*while[^}]*t\[', src)
for m in exec_pattern:
    print(f"Exec function at pos {m.start()}: {src[m.start():m.start()+200]}")

# Look for u[ or u.get patterns (Proxy access)
proxy_access = list(re.finditer(r'u\[', src))
print(f"\nFound {len(proxy_access)} u[ accesses")
for m in proxy_access[:5]:
    print(f"  pos {m.start()}: {src[m.start():m.start()+100]}")

# The dispatch loop is likely function U
U_match = re.search(r'function U\s*\(', src)
if U_match:
    print(f"\nFunction U at pos {U_match.start()}:")
    print(src[U_match.start():U_match.start()+500])

# Alternative: look for the actual dispatch that calls u[opcode]
dispatch_pattern = re.finditer(r'u\[\s*t\s*\[', src)
for m in dispatch_pattern:
    ctx = src[max(0,m.start()-100):m.start()+200]
    print(f"\nDispatch pattern at pos {m.start()}:")
    print(f"  {ctx}")

# Let's look at what comes AFTER the Proxy definition
after_proxy = src[end:end+2000]
print(f"\n{'='*80}")
print("CODE AFTER PROXY DEFINITION (dispatch loop):")
print("=" * 80)
print(after_proxy[:2000])

# Also look at OP_5 handler to understand scope_store_parent
print(f"\n{'='*80}")
print("OP_5 handler (scope_store_parent):")
print(f"  {handlers[5]}")
print()
print("OP_19 handler (scope_set):")
print(f"  {handlers[19]}")
print()

# The key: what does v(n) return?
# v = s = function(e){return e.o[1]}
# This returns frame.o[1] which is the scope metadata object
# The scope object has: {h: window, a: null, s: [], o: [pc], m: parent}
# So scope.s is the variable array, scope.m is parent scope

# For OP_28: for(i=slot, r=value, o=scope; o; o=o.m) if(i in o.s) o.s[i]=r
# This walks UP the scope chain looking for slot i, then writes r to it

# For OP_5: scope.s[e(n)] = scope.a
# scope.a is the "argument" - this stores the function argument into a scope slot

# For OP_19: scope.s[e(n)] = e(n)  
# Direct set of scope slot to a value

print()
print("=" * 80)
print("UNDERSTANDING THE YIELD AND CONTINUATION PATTERN")
print("=" * 80)
print()

# OP_56 handler: function(){return arguments}.apply(void 0,_)
# This is clearly NOT a normal handler. Let me look at it in context.
# The handler array splice might end at index 56.

# Actually wait - let me count the handlers more carefully
print(f"Total handlers in array: {len(handlers)}")
print(f"Handler 55: {handlers[55][:80]}")
print(f"Handler 56: {handlers[56][:200]}")
print(f"Handler 57: {handlers[57][:80]}")
print()

# The handler at index 56 might be a split point in the array construction.
# The minified p.js uses array concatenation to build the handler list.
# "function(){return arguments}.apply(void 0,_)" might be the Array(...) call pattern
# used for array concatenation/spreading.

# Let me look at the raw source more carefully around this handler
# Find where handlers split in the raw source
h56_pos = handler_src.find(handlers[56])
print(f"Handler 56 starts at position {h56_pos} in handler source")
print(f"Context: ...{handler_src[h56_pos-50:h56_pos+250]}...")
print()

# REVELATION: If handler 56 is the array concatenation marker, then 
# the ACTUAL handler for opcode 56 might be different!

# Let's look at the structure: the source uses:
# u = new Proxy([handler0, handler1, ..., function(){return arguments}.apply(void 0, _)], ...)
# The "function(){return arguments}.apply(void 0, _)" is used to SPREAD another array into this one!
# It's: [...firstPart, ...secondPart] compiled as:
# [h0, h1, ..., h55].concat(Array.apply(void 0, [h56, h57, ...]))

# This means handler 56 is NOT "function(){return arguments}.apply(void 0,_)"
# That's the spread syntax! We need to find the actual handler 56.

# Let me look at the split pattern
print("Looking for array concatenation in the Proxy source...")
# Find ].concat or similar
concat_pos = src.find('].concat', proxy_pos)
if concat_pos > 0 and concat_pos < end:
    print(f"Found ].concat at position {concat_pos}")
    print(f"Context: {src[concat_pos-20:concat_pos+200]}")

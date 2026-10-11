"""
Definitive vxn trace with correct understanding of the VM instruction format.

KEY INSIGHT:
- a(n, value) = F(n, value) = n.o[B(n)] = value
- B(n) reads the NEXT bytecode int and shifts right by 5 = register index
- So AFTER every instruction that calls a(n, ...), there's a HIDDEN register store
- This "hidden" byte is consumed from the bytecode but represents the destination register

The instruction format is:
  [opcode] [operand1] [operand2] ... [dest_register_byte (if handler calls a())]

Handlers that call a(n, value): 0,2,3,6,7,8,9,11,12,13,15,16,17,20,21,22,23,24,25,26,27,29,30,31,32,33,35,36,37,38,39,40,41,43,44,46,47,48,49,50,51,52,53,54,55,58,59,61,62,63,64,65,66,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88
Actually wait - not all of those. Let me check which handlers actually call a(n,...).
"""

import re
import json

with open(r"E:\kasada fully reverse\work\vm_section.js", "r") as f:
    src = f.read()

# Find handlers
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

# Determine which handlers call a(n, ...) - these have a dest register after operands
# Also determine which use r[5] (the pop function j)
print("Handler analysis:")
print("=" * 70)

stores_to_reg = []
for idx, h in enumerate(handlers):
    e_count = len(re.findall(r'\be\s*\(\s*n\s*\)', h))
    v_count = len(re.findall(r'\bv\s*\(\s*n\s*\)', h))
    a_calls = len(re.findall(r'\ba\s*\(\s*n\s*,', h))
    j_calls = len(re.findall(r'r\[5\]', h))  # r[5] = j = pop
    o_calls = len(re.findall(r'\bo\s*\(\s*n\s*\)', h))  # o(n) = pop call
    
    has_store = a_calls > 0
    if has_store:
        stores_to_reg.append(idx)

print(f"Handlers that store to register (call a(n,...)): {len(stores_to_reg)}")
print(f"  {stores_to_reg}")
print()

# Now re-examine the critical region with proper understanding
# The F function reads B(n) AFTER the handler returns
# Actually no - F IS a(). The handler calls a(n, value) which calls F(n, value)
# F reads the next bytecode int as register index using B(n)
# B reads t[e.o[0]++]>>5

# So the ACTUAL instruction format for handlers that call a() is:
# [opcode] [operands as decoded by e(n)/v(n)] [dest_register_byte]

# The dest_register_byte is consumed by B(n) inside a(n,value)/F(n,value)
# It's read from the bytecode at the current PC position AFTER operands

# This means our disassembler is WRONG for instructions that store results!
# The "DATA" entries we're seeing are actually the destination register bytes!

print("=" * 70)
print("RE-ANALYZING: DATA entries are actually destination register bytes!")
print("=" * 70)
print()

# Let's verify: look at a simple case
# addr 46274: OP_37(R5 "qdw" 10) - OP_37 is property set: obj[key] = val
# Let's check if OP_37 calls a():
h37 = handlers[37]
print(f"OP_37 handler: {h37}")
a37 = len(re.findall(r'\ba\s*\(\s*n\s*,', h37))
print(f"  Calls a(n,...): {a37}")
print()

# addr 46286: OP_28(393 R5 24) - scope write, no store
# addr 46290: DATA 128 - this IS NOT a DATA, it's the first byte of the next instruction!
# 128 = a register ref: 128 >> 5 = 4, so it's R4
# But wait, 128 as opcode: 128 >= 89 so it IS treated as DATA by the linear sweep

# THE PROBLEM: after OP_28 (which has no a() call), the next byte is just the next opcode
# But if OP_28 doesn't call a(), then the byte after OP_28's operands IS the next opcode
# 128 >= 89 (max opcode) so it's DATA in the linear sweep
# But what if it's consumed differently?

# Actually let me re-think. The handler is called as:
# i(e, G, F, s, n, r) where:
# e = G = operand decoder (reads from bytecode)
# a = F = store function (reads dest register from bytecode)
# v = s = scope accessor
# n = frame

# So when a handler calls a(n, value), it calls F(n, value)
# F does: n.o[B(n)] = value
# B does: t[n.o[0]++] >> 5

# This means F reads ONE MORE INT from the bytecode (the dest register)!
# So after the operands of any instruction that calls a(), there's a dest byte

# Let's recalculate true arities (operands + dest register byte):
print("TRUE byte consumption per opcode:")
print("(operands consumed by e(n)/v(n) + 1 byte for dest if a() is called)")
print()

true_consumption = []
for idx, h in enumerate(handlers):
    e_count = len(re.findall(r'\be\s*\(\s*n\s*\)', h))
    v_count = len(re.findall(r'\bv\s*\(\s*n\s*\)', h))
    a_calls = len(re.findall(r'\ba\s*\(\s*n\s*,', h))
    # r[5] is j (pop), and o(n) is the pop call - these also read from bytecode?
    # Actually looking at how r[5] / j is defined:
    # function j(n){return g(t,n.o,y,P)} - this calls the operand decoder!
    # So o(n) or r[5](n) reads one operand from bytecode!
    
    # Count calls to r[5] and the pop function
    # In the handlers, r[5] is stored as o = r[5]; then o(n) is called
    o_pattern = re.findall(r'o\s*\(\s*n\s*\)', h)
    # But o might be redefined in the handler...
    # Let's look for "var o=r[5]" pattern
    has_pop = 'r[5]' in h
    pop_calls = 0
    if has_pop:
        # Count how many times o(n) is called after o=r[5]
        # This is tricky because 'o' might be reused
        pop_calls = len(re.findall(r'\bo\s*\(\s*n\s*\)', h))
    
    total = 1 + e_count + v_count + pop_calls + (1 if a_calls > 0 else 0)
    # Actually each pop call also consumes from bytecode!
    # But r[5] = j = function(n){return g(t,n.o,y,P)} 
    # g() is the operand decoder - it reads from bytecode!
    
    true_consumption.append({
        'op': idx,
        'e_reads': e_count,
        'v_reads': v_count,
        'pop_reads': pop_calls,
        'has_store': a_calls > 0,
        'handler': h[:100]
    })

# Now let's rebuild the disassembler with correct understanding
# For the critical PoW region

print()
print("=" * 70) 
print("CORRECT DISASSEMBLY OF PoW REGION (46260-46500)")
print("=" * 70)
print()
print("Understanding:")
print("  - After operands, if handler calls a(n,...), NEXT byte = dest register")
print("  - r[5](n) / o(n) = j(n) = reads ANOTHER operand from bytecode (pop)")
print("  - This means many 'DATA' entries are actually consumed by instructions")
print()

# Load program
with open(r"E:\kasada fully reverse\work\program_bytecode.json", "r") as f:
    data = json.load(f)
program = data["ints"]

with open(r"E:\kasada fully reverse\work\string_table.txt", "r") as f:
    P_Q = f.read()

TAGS = [4, 40, 30, 16, 20, 26]

def decode_one_operand(program, ip, P_Q):
    """Decode a single operand, return (repr, new_ip, raw_value)"""
    if ip >= len(program):
        return None, ip, None
    a = program[ip]; ip += 1
    if a & 1:
        return f"{a>>1}", ip, a >> 1
    if a == 4:
        # double - read 2 more
        if ip + 1 < len(program):
            p = program[ip]; x = program[ip+1]; ip += 2
            # Decode IEEE 754
            if p < 0: p += 2**32
            if x < 0: x += 2**32
            sign = -1 if (p & 0x80000000) else 1
            exp = (p & 0x7FF00000) >> 20
            mant = (p & 0xFFFFF) * (2**32) + x
            if exp == 2047:
                return "NaN" if mant else f"{sign}Inf", ip, None
            if exp != 0: mant += 2**52
            else: exp = 1
            val = sign * mant * (2 ** (exp - 1075))
            if val == int(val) and abs(val) < 2**53:
                return f"{int(val)}", ip, int(val)
            return f"{val:.6g}", ip, val
        return "?double", ip, None
    if a == 40: return "null", ip, None
    if a == 30:
        if ip + 1 < len(program):
            length = program[ip]; offset = program[ip+1]; ip += 2
            s = P_Q[offset:offset+length] if offset+length <= len(P_Q) else "???"
            if len(s) > 40: s = s[:40] + "..."
            return f'"{s}"', ip, s
        return '"?"', ip, None
    if a == 16: return "false", ip, False
    if a == 20: return "true", ip, True
    if a == 26: return "void", ip, None
    # Register reference
    return f"R{a>>5}", ip, None

# For each handler, determine exact bytecode consumption
# The challenge is that r[5]/o/j calls are dynamic (pop from eval stack via bytecode read)
# Let me just use the handler info we already have

# Actually, let me take a different approach: 
# The "DATA" entries in the linear sweep at addresses like 46290 (value 128)
# 128 as register: 128 >> 5 = 4 = R4
# Could this be the destination register of the previous instruction?

# OP_28 does NOT call a(), so no dest register. The next byte is a new instruction.
# 128 >= 89 (max valid opcode) so linear sweep marks it as DATA.
# But what IS 128? In the operand decoder, if a byte is even and not a tag:
# it's a register reference. 128 >> 5 = 4 = R4.
# But for it to be consumed as an operand, it must be part of an instruction.

# THE REAL ISSUE: The pop function r[5](n) = j(n) reads operands too!
# Handlers that call o(n) [where o = r[5]] consume EXTRA bytes from bytecode!
# These extra consumed bytes look like "DATA" in the linear sweep because
# the disassembler doesn't account for them.

# Let's count exactly how many bytes each handler consumes:
print("Exact bytecode consumption per handler:")
for idx in [0, 2, 3, 5, 7, 8, 9, 10, 12, 13, 19, 28, 37, 52, 56, 65, 66, 76, 85, 86]:
    h = handlers[idx]
    e_reads = len(re.findall(r'\be\s*\(\s*n\s*\)', h))
    v_reads = len(re.findall(r'\bv\s*\(\s*n\s*\)', h))
    has_store = len(re.findall(r'\ba\s*\(\s*n\s*,', h)) > 0
    
    # Count pop calls: o(n) where o = r[5]
    # Pattern: "var o=r[5]" then "o(n)" calls
    has_pop_var = bool(re.search(r'var\s+o\s*=\s*r\[5\]', h))
    pop_calls = 0
    if has_pop_var:
        pop_calls = len(re.findall(r'\bo\s*\(\s*n\s*\)', h))
    
    total_reads = e_reads + pop_calls  # v_reads don't consume bytecode the same way
    dest = 1 if has_store else 0
    total = 1 + total_reads + dest  # 1 for opcode
    
    # Note: v(n) calls don't directly read from bytecode - they walk scope chain
    # Actually wait - looking at s function:
    # function s(e){return e.o[1]} - just returns the scope metadata
    # So v(n) in handlers = s(n) which returns the scope, not reading bytecode!
    
    print(f"  OP_{idx:2d}: e={e_reads} pop={pop_calls} dest={dest} | total bytes={total} | {h[:60]}")

print()
print("=" * 70)
print("KEY: Handlers using r[5] (pop) that affect the PoW region")
print("=" * 70)

# Let's look specifically at which opcodes near the PoW region use pop
# and how this affects our disassembly
for idx in range(89):
    h = handlers[idx]
    has_pop_var = bool(re.search(r'var\s+o\s*=\s*r\[5\]', h))
    if has_pop_var:
        pop_calls = len(re.findall(r'\bo\s*\(\s*n\s*\)', h))
        e_reads = len(re.findall(r'\be\s*\(\s*n\s*\)', h))
        has_store = len(re.findall(r'\ba\s*\(\s*n\s*,', h)) > 0
        print(f"  OP_{idx:2d}: e={e_reads} pop={pop_calls} dest={'Y' if has_store else 'N'} | {h[:80]}")

print()
print("=" * 70)
print("BUILDING CORRECT ARITY TABLE")
print("=" * 70)
print()

# True arity = number of operands consumed from bytecode
# = e(n) calls + pop/o(n) calls + (1 if has dest register store)
# Note: v(n) does NOT consume from bytecode (it reads scope metadata)

correct_arities = []
for idx, h in enumerate(handlers):
    e_reads = len(re.findall(r'\be\s*\(\s*n\s*\)', h))
    has_store = len(re.findall(r'\ba\s*\(\s*n\s*,', h)) > 0
    
    has_pop_var = bool(re.search(r'var\s+o\s*=\s*r\[5\]', h))
    pop_calls = 0
    if has_pop_var:
        pop_calls = len(re.findall(r'\bo\s*\(\s*n\s*\)', h))
    
    # Total bytecode consumption (excluding the opcode itself)
    total = e_reads + pop_calls + (1 if has_store else 0)
    correct_arities.append(total)

print("CORRECT_ARITIES = [")
for i in range(0, len(correct_arities), 10):
    chunk = correct_arities[i:i+10]
    print(f"    {', '.join(str(x) for x in chunk)},  # ops {i}-{i+len(chunk)-1}")
print("]")

# Now let's compare with the old arities
old_arities = [
    2,1,1,1,1,2,3,1,1,0,2,1,0,1,2,1,1,0,2,3,0,1,0,1,1,1,0,1,3,4,0,1,1,1,2,1,0,3,2,1,1,0,2,2,1,2,0,1,1,0,0,2,1,0,1,3,0,2,0,1,4,0,1,0,2,2,2,1,2,0,0,1,0,0,0,1,1,1,0,0,1,1,0,0,0,3,1,1,3
]

print()
print("Differences between old and correct arities:")
diffs = []
for i, (old, new) in enumerate(zip(old_arities, correct_arities)):
    if old != new:
        diffs.append((i, old, new))
        print(f"  OP_{i:2d}: old={old} new={new} (diff={new-old})")

print(f"\n  Total differences: {len(diffs)}")

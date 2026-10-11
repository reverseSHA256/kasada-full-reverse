"""Extract all hardcoded keys from the bytecode."""
import sys; sys.argv = ['']
exec(open(r'E:\kasada fully reverse\work\disasm_v3.py').read().split('def main():')[0])
import json

with open(r'E:\kasada fully reverse\work\program_bytecode.json', 'r') as f:
    data = json.load(f)
program = data['ints']
with open(r'E:\kasada fully reverse\work\string_table.txt', 'r') as f:
    P_Q = f.read()

def extract_prop_set_value(addr):
    """Extract the 3rd operand (value) of a prop_set at given addr."""
    ip = addr + 1  # skip opcode 37
    # Skip first operand (obj)
    a = program[ip]; ip += 1
    if a & 1: pass
    elif a == 4: ip += 2
    elif a == 30: ip += 2
    # Skip second operand (key)
    a = program[ip]; ip += 1
    if a & 1: pass
    elif a == 4: ip += 2
    elif a == 30: ip += 2
    # Read third operand (value)
    a = program[ip]; ip += 1
    if a & 1:
        return str(a >> 1)
    elif a == 30:
        length = program[ip]; offset = program[ip+1]
        return P_Q[offset:offset+length]
    elif a == 40:
        return "null"
    elif a == 16:
        return "false"
    elif a == 20:
        return "true"
    elif a == 26:
        return "void"
    else:
        return f"R{a>>5}"

# YKJ (HMAC key) at addr 22742
ykj = extract_prop_set_value(22742)
print(f'YKJ (HMAC key):')
print(f'  Value: "{ykj}"')
print(f'  Length: {len(ykj)} chars = {len(ykj)//2} bytes as hex')
print()

# JPK at addr 22706
jpk = extract_prop_set_value(22706)
print(f'JPK (encryption key):')
print(f'  Value: "{jpk}"')
print()

# RPK at addr 22714
rpk = extract_prop_set_value(22714)
print(f'RPK (short key/IV):')
print(f'  Value: "{rpk}"')
print()

# NRP (endpoint) at addr 22803
nrp = extract_prop_set_value(22803)
print(f'NRP (endpoint):')
print(f'  Value: "{nrp}"')
print()

# ZGP (TTL) at addr 22728
zgp = extract_prop_set_value(22728)
print(f'ZGP (TTL):')
print(f'  Value: {zgp}')
print()

# QHC (version) at addr 22784
qhc = extract_prop_set_value(22784)
print(f'QHC (version):')
print(f'  Value: "{qhc}"')
print()

# qdw, xqn from addr 22752, 22758
qdw = extract_prop_set_value(22752)
xqn = extract_prop_set_value(22758)
print(f'QDW (difficulty): {qdw}')
print(f'XQN (rounds): {xqn}')
print()

# zsr from addr 22764
zsr = extract_prop_set_value(22764)
print(f'ZSR (challenge): "{zsr}"')
print()

# Also extract the ykj at 22742 more carefully - might be truncated
# Let me check the raw bytes
ip = 22742
print(f"Raw bytes at 22742: {[program[ip+i] for i in range(15)]}")
# opcode=37, then 3 operands
# First: program[22743] - obj ref
# Second: program[22744..22746] - 'ykj' string (30, 3, offset)
# Third: the value string
ip = 22743
a = program[ip]; ip += 1; print(f"  Obj: raw={a} -> R{a>>5}")
a = program[ip]; ip += 1; print(f"  Key tag: {a}")
if a == 30:
    l = program[ip]; ip += 1
    o = program[ip]; ip += 1
    print(f"  Key: len={l} off={o} -> '{P_Q[o:o+l]}'")
a = program[ip]; ip += 1; print(f"  Val tag: {a}")
if a == 30:
    l = program[ip]; ip += 1
    o = program[ip]; ip += 1
    print(f"  Val: len={l} off={o}")
    full_val = P_Q[o:o+l]
    print(f"  Full YKJ value: '{full_val}'")
    print(f"  Length: {len(full_val)}")

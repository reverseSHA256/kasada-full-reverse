"""
Trace the exact x-kpsdk-h HMAC generation in the bytecode.
We know:
- HMAC key = ykj = "7ae9906d03439b11..."
- The computation is somewhere after the CD generation
- Need to find where x-kpsdk-h string is used and trace backwards
"""

import sys; sys.argv = ['']
exec(open(r'E:\kasada fully reverse\work\disasm_v3.py').read().split('def main():')[0])
import json

with open(r'E:\kasada fully reverse\work\program_bytecode.json', 'r') as f:
    data = json.load(f)
program = data['ints']
with open(r'E:\kasada fully reverse\work\string_table.txt', 'r') as f:
    P_Q = f.read()

def find_string_refs(target):
    results = []
    for ip in range(len(program) - 2):
        if program[ip] == 30:
            length = program[ip+1]
            offset = program[ip+2]
            if length == len(target) and offset + length <= len(P_Q):
                if P_Q[offset:offset+length] == target:
                    results.append(ip)
    return results

# Find x-kpsdk-h references
print("=" * 80)
print("x-kpsdk-h STRING REFERENCES")
print("=" * 80)
refs = find_string_refs('x-kpsdk-h')
print(f"Found {len(refs)} references")
for addr in refs:
    lines = disasm(program, P_Q, max(0, addr-10), addr+30)
    print(f"\n--- near addr {addr} ---")
    for line in lines:
        print(f"  {line}")

# Find 'hmac' references (already found at 22399)
print()
print("=" * 80)
print("'hmac' STRING REFERENCES") 
print("=" * 80)
refs = find_string_refs('hmac')
print(f"Found {len(refs)} references")
for addr in refs:
    lines = disasm(program, P_Q, max(0, addr-5), addr+15)
    print(f"\n--- near addr {addr} ---")
    for line in lines:
        if 'hmac' in line:
            print(f"  >>> {line}")
        else:
            print(f"      {line}")

# Find 'digest' references - HMAC usually calls .digest() or .update()
print()
print("=" * 80)
print("'digest' STRING REFERENCES")
print("=" * 80)
refs = find_string_refs('digest')
print(f"Found {len(refs)} references")
for addr in refs[:8]:
    lines = disasm(program, P_Q, max(0, addr-3), addr+8)
    print(f"\n  --- addr {addr} ---")
    for line in lines:
        if 'digest' in line:
            print(f"    >>> {line}")

# Find 'update' references
print()
print("=" * 80)
print("'update' STRING REFERENCES")
print("=" * 80)
refs = find_string_refs('update')
print(f"Found {len(refs)} references")
for addr in refs[:8]:
    lines = disasm(program, P_Q, max(0, addr-3), addr+8)
    print(f"\n  --- addr {addr} ---")
    for line in lines:
        if 'update' in line:
            print(f"    >>> {line}")

# Find 'create' references (HMAC.create pattern from CryptoJS)
print()
print("=" * 80)
print("'create' STRING REFERENCES")
print("=" * 80)
refs = find_string_refs('create')
print(f"Found {len(refs)} references")
for addr in refs[:5]:
    lines = disasm(program, P_Q, max(0, addr-3), addr+5)
    print(f"\n  --- addr {addr} ---")
    for line in lines:
        if 'create' in line:
            print(f"    >>> {line}")

# Find 'finalize' references
print()
refs = find_string_refs('finalize')
print(f"'finalize' refs: {len(refs)}")
for addr in refs[:5]:
    lines = disasm(program, P_Q, max(0, addr-3), addr+5)
    for line in lines:
        if 'finalize' in line:
            print(f"  {line}")

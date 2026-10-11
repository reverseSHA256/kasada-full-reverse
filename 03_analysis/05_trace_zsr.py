"""
Trace all references to 'zsr', 'ewm', 'yzv' properties 
to understand how they're updated after /tl response.
"""

import sys
sys.argv = ['']
exec(open(r'E:\kasada fully reverse\work\disasm_v3.py').read().split('def main():')[0])

import json
with open(r'E:\kasada fully reverse\work\program_bytecode.json', 'r') as f:
    data = json.load(f)
program = data['ints']
with open(r'E:\kasada fully reverse\work\string_table.txt', 'r') as f:
    P_Q = f.read()

def find_string_refs(target):
    """Find all bytecode positions where a string literal matches target."""
    results = []
    for ip in range(len(program) - 2):
        if program[ip] == 30:  # string tag
            length = program[ip+1]
            offset = program[ip+2]
            if length == len(target) and offset + length <= len(P_Q):
                if P_Q[offset:offset+length] == target:
                    results.append(ip)
    return results

# Find 'zsr' references
print("=" * 80)
print("ALL 'zsr' STRING REFERENCES")
print("=" * 80)
refs = find_string_refs('zsr')
print(f"Found {len(refs)} references to 'zsr'")
for addr in refs:
    lines = disasm(program, P_Q, max(0, addr-5), addr+10)
    print(f"\n  --- bytecode pos {addr} ---")
    for line in lines:
        if 'zsr' in line:
            print(f"    >>> {line}")
        else:
            print(f"        {line}")

# Find 'ewm' references  
print()
print("=" * 80)
print("ALL 'ewm' STRING REFERENCES")
print("=" * 80)
refs = find_string_refs('ewm')
print(f"Found {len(refs)} references to 'ewm'")
for addr in refs:
    lines = disasm(program, P_Q, max(0, addr-5), addr+10)
    print(f"\n  --- bytecode pos {addr} ---")
    for line in lines:
        if 'ewm' in line:
            print(f"    >>> {line}")
        else:
            print(f"        {line}")

# Find 'yzv' references
print()
print("=" * 80)
print("ALL 'yzv' STRING REFERENCES")
print("=" * 80)
refs = find_string_refs('yzv')
print(f"Found {len(refs)} references to 'yzv'")
for addr in refs:
    lines = disasm(program, P_Q, max(0, addr-3), addr+8)
    print(f"\n  --- bytecode pos {addr} ---")
    for line in lines:
        if 'yzv' in line:
            print(f"    >>> {line}")

# Also find 'dynamicConfig' references - this is where /tl response goes
print()
print("=" * 80)
print("'dynamicConfig' REFERENCES")
print("=" * 80)
refs = find_string_refs('dynamicConfig')
print(f"Found {len(refs)} references")
for addr in refs[:5]:
    lines = disasm(program, P_Q, max(0, addr-5), addr+15)
    print(f"\n  --- bytecode pos {addr} ---")
    for line in lines:
        if 'dynamicConfig' in line or 'yzv' in line or 'ewm' in line:
            print(f"    >>> {line}")
        else:
            print(f"        {line}")

# Find where ykj (HMAC key) is used
print()
print("=" * 80)
print("'ykj' STRING REFERENCES (HMAC KEY)")
print("=" * 80)
refs = find_string_refs('ykj')
print(f"Found {len(refs)} references to 'ykj'")
for addr in refs[:8]:
    lines = disasm(program, P_Q, max(0, addr-3), addr+8)
    print(f"\n  --- bytecode pos {addr} ---")
    for line in lines:
        if 'ykj' in line:
            print(f"    >>> {line}")

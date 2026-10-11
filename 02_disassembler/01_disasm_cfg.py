"""
Kasada VM Disassembler with Control Flow Analysis
==================================================
Improvements over the linear-sweep disasm.py:
1. Recursive-descent disassembly following control flow
2. Proper jump target tracking (OP_76, OP_85, OP_88)
3. Function entry point detection (OP_19 scope stores with PC targets)
4. DATA vs instruction disambiguation
5. Cross-reference generation for calls and jumps
"""

import json
import re
import struct
import sys
from collections import defaultdict

# Load bytecode and string table
def load_artifacts(work_dir):
    with open(f"{work_dir}/program_bytecode.json", "r") as f:
        data = json.load(f)
    if isinstance(data, dict) and "ints" in data:
        program = data["ints"]
    elif isinstance(data, list):
        program = data
    else:
        raise ValueError(f"Unexpected JSON format: {type(data)}")
    with open(f"{work_dir}/string_table.txt", "r") as f:
        P_Q = f.read()
    return program, P_Q

# Operand tags
TAGS = [4, 40, 30, 16, 20, 26]
TAG_DOUBLE = 4
TAG_NULL = 40
TAG_STRING = 30
TAG_FALSE = 16
TAG_TRUE = 20
TAG_VOID = 26

# Handler arities (89 opcodes) - from the analysis
ARITIES = [
    2,  # 0: property get
    1,  # 1: set loop target
    1,  # 2: divide
    1,  # 3: XOR
    1,  # 4: set catch handler
    2,  # 5: scope store
    3,  # 6: call 2-arg
    1,  # 7: not-equal
    1,  # 8: in
    0,  # 9: bitwise OR
    2,  # 10: declare scope var
    1,  # 11: new array
    0,  # 12: less-than
    1,  # 13: greater-than
    2,  # 14: scope delete + try/catch
    1,  # 15: less-than
    1,  # 16: typeof
    0,  # 17: divide
    2,  # 18: try/catch/finally
    3,  # 19: scope store
    0,  # 20: new object
    1,  # 21: subtract
    0,  # 22: multiply
    1,  # 23: strict not-equal
    1,  # 24: strict not-equal
    1,  # 25: modulo
    0,  # 26: XOR
    1,  # 27: add
    3,  # 28: scope chain lookup
    4,  # 29: call 3-arg
    0,  # 30: strict equal
    1,  # 31: not-equal
    1,  # 32: bitwise AND
    1,  # 33: multiply
    2,  # 34: save try state
    1,  # 35: bitwise NOT
    0,  # 36: get Promise
    3,  # 37: property set
    2,  # 38: bitwise OR
    1,  # 39: get runtime
    1,  # 40: bitwise OR
    0,  # 41: add
    2,  # 42: store exception state
    2,  # 43: add
    1,  # 44: greater-equal
    2,  # 45: delete property
    0,  # 46: in
    1,  # 47: unsigned right shift
    1,  # 48: logical NOT
    0,  # 49: new array
    0,  # 50: modulo
    2,  # 51: function bind/construct
    1,  # 52: identity
    0,  # 53: left shift
    1,  # 54: unary plus
    3,  # 55: method call
    0,  # 56: yield/return
    2,  # 57: scope chain read
    0,  # 58: greater-than
    1,  # 59: add
    4,  # 60: complex call with try/catch
    0,  # 61: proxy .get result
    1,  # 62: divide
    0,  # 63: subtract
    2,  # 64: new RegExp
    2,  # 65: subtract
    2,  # 66: loose equal
    1,  # 67: throw
    2,  # 68: call 1-arg
    0,  # 69: throw undefined
    0,  # 70: instanceof
    1,  # 71: call 0-arg
    0,  # 72: get exception
    0,  # 73: get Promise resolve
    0,  # 74: return null (halt)
    1,  # 75: strict equal
    1,  # 76: set PC (JUMP)
    1,  # 77: left shift
    0,  # 78: bitwise AND
    0,  # 79: greater-equal
    1,  # 80: less-equal
    1,  # 81: loose equal
    0,  # 82: clear exception
    0,  # 83: get window
    0,  # 84: strict not-equal
    3,  # 85: conditional jump
    1,  # 86: strict equal
    1,  # 87: catch
    3,  # 88: conditional
]

def read_double(ints, ip):
    """Read IEEE 754 double from two consecutive ints"""
    if ip + 1 >= len(ints):
        return None, ip
    p = ints[ip]
    x = ints[ip + 1]
    # Handle sign
    n = -1 if (p & 0x80000000) else 1
    # Handle as unsigned
    if p < 0:
        p += 2**32
    if x < 0:
        x += 2**32
    u = (p & 0x7FF00000) >> 20
    h = (p & 0xFFFFF) * (2**32) + x
    if u == 2047:
        return (float('nan') if h else n * float('inf')), ip + 2
    if u != 0:
        h += 2**52
    else:
        u = 1
    return n * h * (2 ** (u - 1075)), ip + 2


def decode_operand(program, ip, P_Q):
    """
    Decode a single operand starting at ip.
    Returns: (value_repr, new_ip, raw_value_if_int_or_none)
    """
    if ip >= len(program):
        return None, ip, None
    
    a = program[ip]
    ip += 1
    
    # Odd = small integer
    if a & 1:
        val = a >> 1
        return str(val), ip, val
    
    # Tag-based decoding
    if a == TAG_DOUBLE:
        d, ip = read_double(program, ip)
        if d is not None:
            if d == int(d) and abs(d) < 2**53:
                return f"{int(d)}", ip, int(d)
            return f"{d:.6g}", ip, d
        return "NaN", ip, None
    
    if a == TAG_NULL:
        return "null", ip, None
    
    if a == TAG_STRING:
        if ip + 1 >= len(program):
            return '"?"', ip, None
        length = program[ip]
        offset = program[ip + 1]
        ip += 2
        s = P_Q[offset:offset + length] if offset + length <= len(P_Q) else "???"
        # Truncate long strings for display
        if len(s) > 50:
            s = s[:50] + "..."
        return f'"{s}"', ip, s
    
    if a == TAG_FALSE:
        return "false", ip, False
    
    if a == TAG_TRUE:
        return "true", ip, True
    
    if a == TAG_VOID:
        return "void", ip, None
    
    # Register reference
    reg = a >> 5
    return f"R{reg}", ip, None


def disassemble_at(program, ip, P_Q):
    """
    Disassemble a single instruction at ip.
    Returns: (instruction_str, next_ip, jump_targets, is_halt)
    """
    if ip >= len(program):
        return None, ip, [], False
    
    op = program[ip]
    start_ip = ip
    ip += 1
    
    # Check if this is a valid opcode
    if op >= len(ARITIES):
        return f"DATA {op}", ip, [], False
    
    arity = ARITIES[op]
    operands = []
    raw_values = []
    
    for i in range(arity):
        repr_str, ip, raw_val = decode_operand(program, ip, P_Q)
        if repr_str is None:
            break
        operands.append(repr_str)
        raw_values.append(raw_val)
    
    instr_str = f"OP_{op:2d}({' '.join(operands)})"
    
    # Identify jump targets
    jump_targets = []
    is_halt = False
    
    if op == 74:  # return null (halt)
        is_halt = True
    elif op == 76:  # JUMP: set PC = operand
        if raw_values and isinstance(raw_values[0], (int, float)):
            jump_targets.append(int(raw_values[0]))
    elif op == 85:  # CONDITIONAL JUMP: if(val) PC = val else val
        # OP_85(condition, jump_target, fallthrough)
        if len(raw_values) >= 2 and isinstance(raw_values[1], (int, float)):
            jump_targets.append(int(raw_values[1]))
    elif op == 88:  # CONDITIONAL: if(val) val else PC = val
        if len(raw_values) >= 3 and isinstance(raw_values[2], (int, float)):
            jump_targets.append(int(raw_values[2]))
    elif op == 1:  # Set loop target
        if raw_values and isinstance(raw_values[0], (int, float)):
            jump_targets.append(int(raw_values[0]))
    elif op == 4:  # Set catch handler
        if raw_values and isinstance(raw_values[0], (int, float)):
            jump_targets.append(int(raw_values[0]))
    
    return instr_str, ip, jump_targets, is_halt


def recursive_disassemble(program, P_Q, entry_points=None):
    """
    Recursive descent disassembly starting from entry points.
    Follows control flow to avoid DATA desync.
    """
    if entry_points is None:
        entry_points = [0]
    
    # Track which addresses are confirmed instructions
    instructions = {}  # addr -> instruction string
    visited = set()
    work_queue = list(entry_points)
    jump_targets = defaultdict(set)  # target_addr -> set of source addrs
    function_entries = set()
    
    while work_queue:
        ip = work_queue.pop(0)
        if ip in visited or ip < 0 or ip >= len(program):
            continue
        visited.add(ip)
        
        instr_str, next_ip, targets, is_halt = disassemble_at(program, ip, P_Q)
        if instr_str is None:
            continue
        
        instructions[ip] = instr_str
        
        # Record jump targets and add them to work queue
        for t in targets:
            if 0 <= t < len(program):
                jump_targets[t].add(ip)
                work_queue.append(t)
        
        # Continue to next instruction (fallthrough) unless it's a halt or unconditional jump
        if not is_halt:
            op = program[ip]
            if op != 76:  # Not unconditional jump - add fallthrough
                work_queue.append(next_ip)
            else:
                # Unconditional jump - also add next as potential target (could be a function)
                # Actually for KASADA, the next instruction after a jump is often a function entry
                work_queue.append(next_ip)
    
    return instructions, jump_targets


def linear_disassemble(program, P_Q, max_instr=None):
    """
    Linear sweep disassembly (improved version).
    Falls back to DATA for unrecognized opcodes.
    """
    ip = 0
    instructions = []
    
    while ip < len(program):
        if max_instr and len(instructions) >= max_instr:
            break
        
        start = ip
        op = program[ip]
        
        if op >= len(ARITIES):
            instructions.append((start, f"DATA {op}"))
            ip += 1
            continue
        
        ip += 1
        arity = ARITIES[op]
        operands = []
        valid = True
        
        for _ in range(arity):
            repr_str, ip, raw_val = decode_operand(program, ip, P_Q)
            if repr_str is None:
                valid = False
                break
            operands.append(repr_str)
        
        if valid:
            instructions.append((start, f"OP_{op:2d}({' '.join(operands)})"))
        else:
            instructions.append((start, f"DATA {op}  ; invalid"))
            ip = start + 1
    
    return instructions


def find_string_refs(program, P_Q, target_string):
    """Find all bytecode locations that reference a given string"""
    results = []
    ip = 0
    while ip < len(program) - 2:
        if program[ip] == TAG_STRING:
            length = program[ip + 1]
            offset = program[ip + 2]
            if offset + length <= len(P_Q):
                s = P_Q[offset:offset + length]
                if target_string in s:
                    results.append((ip, s))
        ip += 1
    return results


def find_pow_region(program, P_Q):
    """Find the PoW mining region by looking for key strings"""
    markers = {
        "tp-v2-input": [],
        "exn": [],
        "vxn": [],
        "qdw": [],
        "xqn": [],
        "answers": [],
        "workTime": [],
        "sha256": [],
        "concat": [],
        "slice": [],
    }
    
    for target in markers:
        refs = find_string_refs(program, P_Q, target)
        markers[target] = [r[0] for r in refs]
    
    return markers


def trace_backwards(instructions_list, target_addr, register, max_depth=200):
    """
    Trace backwards from target_addr to find what set a given register.
    Returns list of candidate instructions that could have set the register.
    """
    # Sort instructions by address
    sorted_instrs = sorted(instructions_list, key=lambda x: x[0])
    
    # Find the instruction at or just before target_addr
    target_idx = None
    for i, (addr, instr) in enumerate(sorted_instrs):
        if addr >= target_addr:
            target_idx = i
            break
    
    if target_idx is None:
        return []
    
    # Search backwards for instructions that write to the register
    reg_pattern = f"R{register}"
    candidates = []
    
    for i in range(target_idx - 1, max(0, target_idx - max_depth), -1):
        addr, instr = sorted_instrs[i]
        # OP_52 (identity/store), OP_55 (method call result), OP_28 (scope lookup)
        # These write to registers
        if f"OP_52({reg_pattern})" in instr or f"OP_28(" in instr:
            candidates.append((addr, instr))
        elif f"OP_55(" in instr and reg_pattern in instr:
            candidates.append((addr, instr))
        elif f"OP_ 0(" in instr and reg_pattern in instr:
            candidates.append((addr, instr))
        elif f"OP_65(" in instr and reg_pattern in instr:
            candidates.append((addr, instr))
    
    return candidates


def main():
    work_dir = r"E:\kasada fully reverse\work"
    
    print("Loading bytecode and string table...")
    program, P_Q = load_artifacts(work_dir)
    print(f"  Program: {len(program)} ints")
    print(f"  String table: {len(P_Q)} chars")
    print()
    
    # Find PoW-related string references
    print("=" * 70)
    print("PHASE 1: Finding PoW-related string references")
    print("=" * 70)
    markers = find_pow_region(program, P_Q)
    for key, addrs in markers.items():
        if addrs:
            print(f"  {key:15s}: {addrs[:10]}")
    print()
    
    # Do a linear disassembly of the region around the PoW
    print("=" * 70)
    print("PHASE 2: Disassembling PoW region")
    print("=" * 70)
    
    # Find the "tp-v2-input" reference - this is near the PoW initialization
    tp_refs = find_string_refs(program, P_Q, "tp-v2-input")
    print(f"\n  'tp-v2-input' references: {[(r[0], r[1]) for r in tp_refs]}")
    
    # Find "vxn" references
    vxn_refs = find_string_refs(program, P_Q, "vxn")
    print(f"  'vxn' references: {[(r[0], r[1]) for r in vxn_refs]}")
    
    # Find "exn" references
    exn_refs = find_string_refs(program, P_Q, "exn")
    print(f"  'exn' references: {[(r[0], r[1]) for r in exn_refs]}")
    
    # Find "answers" references
    ans_refs = find_string_refs(program, P_Q, "answers")
    print(f"  'answers' references: {[(r[0], r[1]) for r in ans_refs]}")
    
    # Disassemble around the vxn region
    if vxn_refs:
        # Find the earliest vxn reference
        vxn_addr = min(r[0] for r in vxn_refs)
        # Go back ~100 ints to capture context
        start = max(0, vxn_addr - 150)
        end = min(len(program), vxn_addr + 300)
        
        print(f"\n  Disassembling region around vxn ({start}-{end}):")
        print("-" * 70)
        
        # Linear disassemble just this region
        region = program[start:end]
        ip = 0
        while ip < len(region):
            abs_addr = start + ip
            op = region[ip]
            if op >= len(ARITIES):
                print(f"  {abs_addr:6d}  DATA {op}")
                ip += 1
                continue
            
            instr_str, next_ip, targets, is_halt = disassemble_at(region, ip, P_Q)
            if instr_str:
                # Highlight vxn-related instructions
                marker = " <-- VXN" if "vxn" in instr_str.lower() else ""
                marker = " <-- TP-V2" if "tp-v2-input" in instr_str else marker
                marker = " <-- EXN" if '"exn"' in instr_str else marker
                print(f"  {abs_addr:6d}  {instr_str}{marker}")
            ip = next_ip
    
    # Now let's trace what feeds into vxn
    print()
    print("=" * 70)
    print("PHASE 3: Tracing vxn data flow")
    print("=" * 70)
    
    # Find OP_37 instructions that set "vxn" property
    print("\n  Looking for OP_37(...\"vxn\"...) patterns in bytecode...")
    ip = 0
    vxn_sets = []
    while ip < len(program) - 5:
        if program[ip] == 37:  # OP_37 (property set)
            # OP_37 has arity 3: obj[key] = val
            # We need to decode the operands to find "vxn"
            test_ip = ip + 1
            # Try to decode 3 operands
            ops = []
            valid = True
            for _ in range(3):
                repr_str, test_ip, raw_val = decode_operand(program, test_ip, P_Q)
                if repr_str is None:
                    valid = False
                    break
                ops.append((repr_str, raw_val))
            
            if valid and len(ops) == 3:
                # Check if any operand is "vxn"
                if any("vxn" in str(o[0]) for o in ops):
                    vxn_sets.append((ip, ops))
                    print(f"    addr {ip}: OP_37({ops[0][0]} {ops[1][0]} {ops[2][0]})")
        ip += 1
    
    # Now find where the value register comes from
    print(f"\n  Found {len(vxn_sets)} OP_37 instructions setting 'vxn'")
    
    if vxn_sets:
        for addr, ops in vxn_sets:
            # The value is the 3rd operand
            val_repr = ops[2][0]
            print(f"\n  At addr {addr}: vxn = {val_repr}")
            if val_repr.startswith("R"):
                reg_num = int(val_repr[1:])
                print(f"    Value comes from register R{reg_num}")
                print(f"    Searching backwards for R{reg_num} assignments...")
                
                # Search backwards in a window
                window_start = max(0, addr - 500)
                window_instrs = []
                wip = window_start
                while wip < addr:
                    op_val = program[wip]
                    if op_val < len(ARITIES):
                        instr_str, next_wip, _, _ = disassemble_at(program, wip, P_Q)
                        if instr_str:
                            window_instrs.append((wip, instr_str))
                        wip = next_wip
                    else:
                        wip += 1
                
                # Find what wrote to the register
                candidates = []
                for w_addr, w_instr in reversed(window_instrs):
                    # Check if this instruction writes to our target register
                    # OP_52(Rn) stores to the instruction's implicit target
                    # But actually in Kasada VM, F(e,n) = e.o[B(e)] = n
                    # The store target is the NEXT byte after the opcode which is a register
                    # This is complex - let's just look for the register in instructions
                    if val_repr in w_instr:
                        candidates.append((w_addr, w_instr))
                        if len(candidates) >= 20:
                            break
                
                print(f"    Last {min(20, len(candidates))} references to {val_repr} before addr {addr}:")
                for c_addr, c_instr in candidates[:20]:
                    print(f"      {c_addr:6d}  {c_instr}")
    
    # Find the /tl response processing
    print()
    print("=" * 70)
    print("PHASE 4: Finding /tl response processing")
    print("=" * 70)
    
    tl_refs = find_string_refs(program, P_Q, "/tl")
    print(f"\n  '/tl' references: {[(r[0], r[1][:40]) for r in tl_refs]}")
    
    # Find encodedClientToken references
    ect_refs = find_string_refs(program, P_Q, "encodedClientToken")
    print(f"  'encodedClientToken' references: {[(r[0], r[1][:40]) for r in ect_refs]}")
    
    # Find dynamicConfig references
    dc_refs = find_string_refs(program, P_Q, "dynamicConfig")
    print(f"  'dynamicConfig' references: {[(r[0], r[1][:40]) for r in dc_refs]}")
    
    # Find HMAC-related
    print()
    print("=" * 70)
    print("PHASE 5: Finding HMAC computation")
    print("=" * 70)
    
    hmac_refs = find_string_refs(program, P_Q, "hmac")
    print(f"\n  'hmac' references: {[(r[0], r[1][:40]) for r in hmac_refs]}")
    
    kpsdk_h_refs = find_string_refs(program, P_Q, "x-kpsdk-h")
    print(f"  'x-kpsdk-h' references: {[(r[0], r[1][:40]) for r in kpsdk_h_refs]}")
    
    kpsdk_cd_refs = find_string_refs(program, P_Q, "x-kpsdk-cd")
    print(f"  'x-kpsdk-cd' references: {[(r[0], r[1][:40]) for r in kpsdk_cd_refs]}")
    
    kpsdk_ct_refs = find_string_refs(program, P_Q, "x-kpsdk-ct")
    print(f"  'x-kpsdk-ct' references: {[(r[0], r[1][:40]) for r in kpsdk_ct_refs]}")
    
    # Find the createHash / sha256 call sites
    ch_refs = find_string_refs(program, P_Q, "createHash")
    print(f"  'createHash' references: {[(r[0], r[1][:40]) for r in ch_refs]}")
    
    # Save full improved disassembly
    print()
    print("=" * 70)
    print("PHASE 6: Generating full improved disassembly")
    print("=" * 70)
    
    instructions = linear_disassemble(program, P_Q)
    
    # Write output
    output_path = f"{work_dir}/disasm_improved.txt"
    with open(output_path, "w", encoding="utf-8") as f:
        # Write header with cross-reference info
        f.write("# Kasada VM Improved Disassembly\n")
        f.write(f"# Program size: {len(program)} ints\n")
        f.write(f"# String table: {len(P_Q)} chars\n")
        f.write(f"# Instructions: {len(instructions)}\n")
        f.write(f"# PoW markers: tp-v2-input @ {[r[0] for r in tp_refs]}\n")
        f.write(f"# vxn markers: {[r[0] for r in vxn_refs]}\n")
        f.write(f"# exn markers: {[r[0] for r in exn_refs]}\n")
        f.write("#\n")
        f.write("# Legend:\n")
        f.write("#   OP_XX(...) = instruction with operands\n")
        f.write("#   DATA N = raw data (not an instruction)\n")
        f.write("#   R<N> = register reference\n")
        f.write("#   \"...\" = string from string table\n")
        f.write("#\n\n")
        
        for addr, instr in instructions:
            f.write(f"{addr:6d}  {instr}\n")
    
    print(f"  Written {len(instructions)} instructions to {output_path}")
    print(f"  File size: {len(instructions)} lines")
    
    # Generate annotated PoW region
    pow_output = f"{work_dir}/pow_region_annotated.txt"
    with open(pow_output, "w", encoding="utf-8") as f:
        f.write("# Kasada PoW Region - Annotated Disassembly\n")
        f.write("# Focus: vxn origin tracing\n\n")
        
        if vxn_refs:
            first_vxn = min(r[0] for r in vxn_refs)
            last_vxn = max(r[0] for r in vxn_refs)
            
            # Wider region including /tl processing before PoW
            region_start = max(0, first_vxn - 1000)
            region_end = min(len(program), last_vxn + 500)
            
            f.write(f"# Region: {region_start} - {region_end}\n")
            f.write(f"# vxn addresses: {[r[0] for r in vxn_refs]}\n")
            f.write(f"# tp-v2-input addresses: {[r[0] for r in tp_refs]}\n\n")
            
            ip = region_start
            while ip < region_end:
                op = program[ip]
                if op >= len(ARITIES):
                    f.write(f"{ip:6d}  DATA {op}\n")
                    ip += 1
                    continue
                
                instr_str, next_ip, targets, is_halt = disassemble_at(program, ip, P_Q)
                if instr_str:
                    # Add annotations
                    ann = ""
                    if "vxn" in instr_str:
                        ann = "  ; <<< VXN ASSIGNMENT/ACCESS"
                    elif "exn" in instr_str:
                        ann = "  ; <<< EXN (PoW seed)"
                    elif "tp-v2-input" in instr_str:
                        ann = "  ; <<< PoW SEED PREFIX"
                    elif "concat" in instr_str:
                        ann = "  ; string concatenation"
                    elif "sha256" in instr_str:
                        ann = "  ; <<< SHA-256 HASH"
                    elif "slice" in instr_str:
                        ann = "  ; string slicing"
                    elif "answers" in instr_str:
                        ann = "  ; <<< PoW ANSWERS"
                    elif "push" in instr_str:
                        ann = "  ; array push"
                    elif "length" in instr_str:
                        ann = "  ; length check"
                    elif "workTime" in instr_str:
                        ann = "  ; <<< CD TOKEN FIELD"
                    elif "duration" in instr_str:
                        ann = "  ; <<< CD TOKEN FIELD"
                    elif "OP_76" in instr_str:
                        ann = "  ; JUMP"
                    elif "OP_85" in instr_str:
                        ann = "  ; CONDITIONAL JUMP"
                    elif "OP_28" in instr_str:
                        ann = "  ; scope chain lookup"
                    
                    f.write(f"{ip:6d}  {instr_str}{ann}\n")
                ip = next_ip
    
    print(f"  Written annotated PoW region to {pow_output}")
    
    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()

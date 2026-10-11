"""
Kasada VM Correct Disassembler
==============================
Uses the TRUE bytecode consumption per opcode:
- e(n) reads = standard operand decoder calls
- o(n)/r[5](n) reads = pop function calls (also reads from bytecode via g())
- dest register byte = consumed by a(n,...) -> F(n,...) -> B(n) = t[pc++]>>5

Key insight: The pop function j(n) = g(t, n.o, y, P) reads the SAME bytecode
stream as e(n). So pop operands are decoded the same way as regular operands.
The dest register byte is a raw int read with >>5 to get register index.
"""

import json
import re
import sys

def load_data(work_dir):
    with open(f"{work_dir}/program_bytecode.json", "r") as f:
        data = json.load(f)
    program = data["ints"] if isinstance(data, dict) and "ints" in data else data
    with open(f"{work_dir}/string_table.txt", "r") as f:
        P_Q = f.read()
    return program, P_Q

TAGS = [4, 40, 30, 16, 20, 26]

# Correct byte consumption: (e_reads, pop_reads, has_dest_store)
# Total consumption from bytecode = 1 (opcode) + e_reads + pop_reads + (1 if has_dest)
# BUT: pop reads use the same decoder as e reads (both call g() on the bytecode)
# AND: dest byte is a raw read of one int, shifted >>5 for register index

HANDLER_INFO = [
    # (e_reads, pop_reads, has_dest, semantics)
    (2, 0, True, "prop_get"),      # 0: a(n, e(n)[e(n)])
    (1, 0, False, "set_loop"),     # 1: n.o[1].l = e(n)
    (1, 1, True, "div"),           # 2: a(n, pop/e(n))
    (1, 1, True, "xor"),           # 3: a(n, e(n)^pop)
    (1, 0, False, "set_catch"),    # 4: n.o[1].i = e(n)
    (1, 0, False, "scope_store"),  # 5: scope.s[e(n)] = scope.a
    (3, 0, True, "call2"),         # 6: a(n, e(n)(e(n), e(n)))
    (1, 1, True, "neq"),           # 7: a(n, pop != e(n))
    (1, 1, True, "in"),            # 8: a(n, e(n) in pop)
    (0, 2, True, "bitor"),         # 9: a(n, pop | pop)
    (1, 0, False, "scope_decl"),   # 10: scope.s[e(n)] = void 0
    (1, 0, True, "new_arr"),       # 11: a(n, new Array(e(n)))
    (0, 2, True, "lt"),            # 12: a(n, pop < pop)
    (1, 1, True, "gt"),            # 13: a(n, pop > e(n))
    (1, 0, False, "scope_del"),    # 14: complex scope/try
    (1, 1, True, "lt2"),           # 15: a(n, pop < e(n))
    (1, 0, True, "typeof"),        # 16: a(n, typeof e(n))
    (0, 2, True, "div2"),          # 17: a(n, pop / pop)
    (1, 0, False, "try_catch"),    # 18: complex control flow
    (2, 0, False, "scope_set"),    # 19: scope.s[e(n)] = e(n)
    (0, 0, True, "new_obj"),       # 20: a(n, {})
    (1, 1, True, "sub"),           # 21: a(n, pop - e(n))
    (0, 2, True, "mul"),           # 22: a(n, pop * pop)
    (1, 1, True, "sneq"),          # 23: a(n, e(n) !== pop)
    (1, 1, True, "sneq2"),         # 24: a(n, pop !== e(n))
    (1, 1, True, "mod"),           # 25: a(n, pop % e(n))
    (0, 2, True, "xor2"),          # 26: a(n, pop ^ pop)
    (1, 1, True, "add"),           # 27: a(n, e(n) + pop)
    (2, 0, False, "scope_write"),  # 28: scope[e(n)] = e(n) (walk chain)
    (4, 0, True, "call3"),         # 29: a(n, e(n)(e(n), e(n), e(n)))
    (0, 2, True, "seq"),           # 30: a(n, pop === pop)
    (1, 1, True, "neq2"),          # 31: a(n, e(n) != pop)
    (1, 1, True, "band"),          # 32: a(n, pop & e(n))
    (1, 1, True, "mul2"),          # 33: a(n, pop * e(n))
    (1, 0, False, "save_try"),     # 34: save try state
    (1, 0, True, "bnot"),          # 35: a(n, ~e(n))
    (0, 0, True, "get_promise"),   # 36: a(n, i[1][0])
    (3, 0, False, "prop_set"),     # 37: e(n)[e(n)] = e(n)
    (2, 0, True, "bitor2"),        # 38: a(n, e(n) | e(n))
    (1, 0, True, "get_runtime"),   # 39: a(n, i[0][e(n)])
    (1, 1, True, "bitor3"),        # 40: a(n, e(n) | pop)
    (0, 2, True, "add2"),          # 41: a(n, pop + pop)
    (1, 0, False, "store_exc"),    # 42: store exception state
    (2, 0, True, "add3"),          # 43: a(n, e(n) + e(n))
    (1, 1, True, "gte"),           # 44: a(n, pop >= e(n))
    (2, 0, True, "del_prop"),      # 45: a(n, delete v[i])
    (0, 2, True, "in2"),           # 46: a(n, pop in pop)
    (1, 1, True, "ushr"),          # 47: a(n, pop >>> e(n))
    (1, 0, True, "lnot"),          # 48: a(n, !e(n))
    (0, 0, True, "new_arr2"),      # 49: a(n, [])
    (0, 2, True, "mod2"),          # 50: a(n, pop % pop)
    (2, 0, True, "construct"),     # 51: a(n, new (bind.apply(...)))
    (1, 0, True, "identity"),      # 52: a(n, e(n))
    (0, 2, True, "shl"),           # 53: a(n, pop << pop)
    (1, 0, True, "uplus"),         # 54: a(n, +e(n))
    (3, 0, True, "method_call"),   # 55: a(n, e(n)[e(n)](e(n)))
    (0, 0, False, "yield"),        # 56: return from handler
    (1, 0, True, "scope_read"),    # 57: a(n, scope[e(n)]) walk chain
    (0, 2, True, "gt2"),           # 58: a(n, pop > pop)
    (1, 1, True, "add4"),          # 59: a(n, pop + e(n))
    (3, 0, False, "call_try"),     # 60: complex call with try
    (0, 0, True, "proxy_get"),     # 61: proxy handler result
    (1, 1, True, "div3"),          # 62: a(n, e(n) / pop)
    (0, 2, True, "sub2"),          # 63: a(n, pop - pop)
    (2, 0, True, "new_regex"),     # 64: a(n, new RegExp(e(n), e(n)))
    (2, 0, True, "sub3"),          # 65: a(n, e(n) - e(n))
    (2, 0, True, "eq"),            # 66: a(n, e(n) == e(n))
    (1, 0, False, "throw"),        # 67: X(n, e(n))
    (2, 0, True, "call1"),         # 68: a(n, e(n)(e(n)))
    (0, 0, False, "throw_undef"),  # 69: X(n, void 0)
    (0, 2, True, "instanceof"),    # 70: a(n, pop instanceof pop)
    (1, 0, True, "call0"),         # 71: a(n, e(n)())
    (0, 0, True, "get_exc"),       # 72: a(n, n.n && n.n.Z)
    (0, 0, True, "get_resolve"),   # 73: a(n, i[1][1])
    (0, 0, False, "halt"),         # 74: return null
    (1, 1, True, "seq2"),          # 75: a(n, e(n) === pop)
    (1, 0, False, "jump"),         # 76: n.o[0] = e(n)
    (1, 1, True, "shl2"),          # 77: a(n, pop << e(n))
    (0, 2, True, "band2"),         # 78: a(n, pop & pop)
    (0, 2, True, "gte2"),          # 79: a(n, pop >= pop)
    (1, 1, True, "lte"),           # 80: a(n, pop <= e(n))
    (1, 1, True, "eq2"),           # 81: a(n, e(n) == pop)
    (0, 0, False, "clear_exc"),    # 82: n.n = void 0
    (0, 0, True, "get_window"),    # 83: a(n, n.o[1].h)
    (0, 2, True, "sneq3"),         # 84: a(n, pop !== pop)
    (3, 0, False, "cond_jump"),    # 85: e(n)?n.o[0]=e(n):e(n)
    (1, 1, True, "seq3"),          # 86: a(n, pop === e(n))
    (1, 0, False, "catch"),        # 87: D(n, e(n))
    (3, 0, False, "cond"),         # 88: e(n)?e(n):n.o[0]=e(n)
]

def decode_operand(program, ip, P_Q):
    """Decode one operand from bytecode. Returns (repr, new_ip, raw_val)"""
    if ip >= len(program):
        return None, ip, None
    a = program[ip]; ip += 1
    if a & 1:
        return f"{a>>1}", ip, a >> 1
    if a == 4:  # double
        if ip + 1 < len(program):
            p, x = program[ip], program[ip+1]; ip += 2
            if p < 0: p += 2**32
            if x < 0: x += 2**32
            sign = -1 if (p & 0x80000000) else 1
            exp = (p & 0x7FF00000) >> 20
            mant = (p & 0xFFFFF) * (2**32) + x
            if exp == 2047:
                return ("NaN" if mant else f"{sign}Inf"), ip, None
            if exp != 0: mant += 2**52
            else: exp = 1
            val = sign * mant * (2 ** (exp - 1075))
            if val == int(val) and abs(val) < 2**53:
                return f"{int(val)}", ip, int(val)
            return f"{val:.6g}", ip, val
        return "?", ip, None
    if a == 40: return "null", ip, None
    if a == 30:
        if ip + 1 < len(program):
            length, offset = program[ip], program[ip+1]; ip += 2
            s = P_Q[offset:offset+length] if offset+length <= len(P_Q) else "???"
            if len(s) > 50: s = s[:50] + "..."
            return f'"{s}"', ip, s
        return '"?"', ip, None
    if a == 16: return "false", ip, False
    if a == 20: return "true", ip, True
    if a == 26: return "void", ip, None
    return f"R{a>>5}", ip, None

def decode_dest_reg(program, ip):
    """Decode destination register byte (raw int >> 5)"""
    if ip >= len(program):
        return None, ip
    val = program[ip]; ip += 1
    return f"R{val >> 5}", ip

def disassemble(program, P_Q, start=0, end=None, annotate=True):
    """Correct disassembly with proper byte consumption."""
    if end is None:
        end = len(program)
    
    instructions = []
    ip = start
    
    while ip < end:
        addr = ip
        op = program[ip]; ip += 1
        
        if op >= len(HANDLER_INFO):
            instructions.append((addr, f"DATA {op}", ""))
            continue
        
        e_reads, pop_reads, has_dest, sem = HANDLER_INFO[op]
        
        # Read e(n) operands
        e_ops = []
        for _ in range(e_reads):
            r, ip, raw = decode_operand(program, ip, P_Q)
            if r is None: r = "?"
            e_ops.append(r)
        
        # Read pop/o(n) operands
        pop_ops = []
        for _ in range(pop_reads):
            r, ip, raw = decode_operand(program, ip, P_Q)
            if r is None: r = "?"
            pop_ops.append(r)
        
        # Read dest register
        dest = ""
        if has_dest:
            d, ip = decode_dest_reg(program, ip)
            dest = f" -> {d}" if d else ""
        
        # Format instruction
        all_ops = []
        if pop_ops:
            all_ops.extend([f"pop:{p}" for p in pop_ops])
        all_ops.extend(e_ops)
        
        instr = f"OP_{op:2d}({', '.join(all_ops)}){dest}"
        
        # Annotation
        ann = ""
        if annotate:
            full_str = " ".join(all_ops)
            if "vxn" in full_str: ann = " ; <<< VXN"
            elif "exn" in full_str: ann = " ; <<< EXN"
            elif "tp-v2-input" in full_str: ann = " ; <<< PoW SEED"
            elif "sha256" in full_str: ann = " ; <<< SHA-256"
            elif "concat" in full_str: ann = " ; concat"
            elif "slice" in full_str: ann = " ; slice"
            elif "answers" in full_str: ann = " ; PoW answers"
            elif "push" in full_str: ann = " ; push"
            elif "workTime" in full_str: ann = " ; CD field"
            elif "hmac" in full_str: ann = " ; <<< HMAC"
            elif "x-kpsdk" in full_str: ann = " ; <<< KPSDK HEADER"
            elif "encodedClientToken" in full_str: ann = " ; CT processing"
            elif "dynamicConfig" in full_str: ann = " ; dynamic config"
            elif sem == "jump": ann = f" ; JUMP to {e_ops[0] if e_ops else '?'}"
            elif sem == "cond_jump": ann = " ; COND JUMP"
            elif sem == "halt": ann = " ; HALT"
            elif sem == "scope_write": ann = f" ; scope[{e_ops[0]}] = {e_ops[1] if len(e_ops)>1 else '?'}"
            elif sem == "scope_read": ann = f" ; read scope[{e_ops[0]}]"
        
        instructions.append((addr, instr, ann))
    
    return instructions


def main():
    work_dir = r"E:\kasada fully reverse\work"
    program, P_Q = load_data(work_dir)
    
    print(f"Program: {len(program)} ints, String table: {len(P_Q)} chars")
    print()
    
    # Disassemble the critical PoW region (46250-46600)
    print("=" * 80)
    print("CORRECT DISASSEMBLY: PoW Region (46250-46600)")
    print("=" * 80)
    print()
    
    instrs = disassemble(program, P_Q, 46250, 46600)
    for addr, instr, ann in instrs:
        print(f"  {addr:6d}  {instr}{ann}")
    
    # Also disassemble the region where scope 393 is initialized (around 5266)
    print()
    print("=" * 80)
    print("SCOPE 393 INITIALIZATION (around addr 5266)")
    print("=" * 80)
    print()
    
    instrs = disassemble(program, P_Q, 5240, 5340)
    for addr, instr, ann in instrs:
        print(f"  {addr:6d}  {instr}{ann}")
    
    # Disassemble the HMAC region (around 22401)
    print()
    print("=" * 80)
    print("HMAC REGION (around addr 22401)")
    print("=" * 80)
    print()
    
    instrs = disassemble(program, P_Q, 22360, 22470)
    for addr, instr, ann in instrs:
        print(f"  {addr:6d}  {instr}{ann}")
    
    # Disassemble around x-kpsdk-h (addr 25008)
    print()
    print("=" * 80)
    print("X-KPSDK-H REGION (around addr 25008)")
    print("=" * 80)
    print()
    
    instrs = disassemble(program, P_Q, 24960, 25060)
    for addr, instr, ann in instrs:
        print(f"  {addr:6d}  {instr}{ann}")
    
    # Save full correct disassembly
    print()
    print("Generating full correct disassembly...")
    instrs = disassemble(program, P_Q, 0, len(program), annotate=False)
    
    with open(f"{work_dir}/disasm_v2.txt", "w", encoding="utf-8") as f:
        f.write(f"# Correct Kasada VM Disassembly (with pop + dest register)\n")
        f.write(f"# Program: {len(program)} ints\n")
        f.write(f"# Instructions decoded: {len(instrs)}\n\n")
        for addr, instr, ann in instrs:
            f.write(f"{addr:6d}  {instr}{ann}\n")
    
    print(f"Written {len(instrs)} instructions to disasm_v2.txt")


if __name__ == "__main__":
    main()

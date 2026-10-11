"""
Kasada VM Disassembler V3 - CORRECT 87-handler table
=====================================================
Fixed handler extraction using proper brace matching.
OP_55 = method_call (3 operands, no dest - manages own frames)
OP_56 = scope_chain_read (1 operand + dest)
OP_72 = halt (returns null)
"""

import json
import re

def load(work_dir):
    with open(f"{work_dir}/program_bytecode.json", "r") as f:
        data = json.load(f)
    program = data["ints"] if isinstance(data, dict) and "ints" in data else data
    with open(f"{work_dir}/string_table.txt", "r") as f:
        P_Q = f.read()
    return program, P_Q

# CORRECT handler table from proper extraction (87 handlers)
# Format: (e_reads, pop_reads, has_dest, total_bc_consumption, semantics)
# total_bc = e_reads + pop_reads + (1 if has_dest else 0)  [excl opcode byte]
HANDLERS = [
    # (e_reads, pop_reads, has_dest, name)
    (2, 0, True, "prop_get"),          # 0: a(n, e(n)[e(n)])
    (1, 0, False, "set_loop_addr"),    # 1: n.o[1].l = e(n)
    (1, 1, True, "div"),               # 2: a(n, pop / e(n))
    (1, 1, True, "xor"),               # 3: a(n, e(n) ^ pop)
    (1, 0, False, "set_catch_addr"),   # 4: n.o[1].i = e(n)
    (1, 0, False, "scope_store_a"),    # 5: scope.s[e(n)] = scope.a  (store parent/arg)
    (3, 0, True, "call2"),             # 6: a(n, e(n)(e(n), e(n)))
    (1, 1, True, "ne"),                # 7: a(n, pop != e(n))
    (1, 1, True, "in"),                # 8: a(n, e(n) in pop)
    (0, 2, True, "bitor"),             # 9: a(n, pop | pop)
    (1, 0, False, "scope_decl"),       # 10: scope.s[e(n)] = undefined
    (1, 0, True, "new_array"),         # 11: a(n, new Array(e(n)))
    (0, 2, True, "lt"),                # 12: a(n, pop < pop)
    (1, 1, True, "gt"),                # 13: a(n, pop > e(n))
    (1, 0, False, "restore_try"),      # 14: restore try state
    (1, 1, True, "lt2"),               # 15: a(n, pop < e(n))
    (1, 0, True, "typeof"),            # 16: a(n, typeof e(n))
    (0, 2, True, "div2"),              # 17: a(n, pop / pop)
    (1, 0, False, "setup_try"),        # 18: setup try/catch/finally
    (2, 0, False, "scope_set"),        # 19: scope.s[e(n)] = e(n)
    (0, 0, True, "new_obj"),           # 20: a(n, {})
    (1, 1, True, "sub"),               # 21: a(n, pop - e(n))
    (0, 2, True, "mul"),               # 22: a(n, pop * pop)
    (1, 1, True, "strict_ne"),         # 23: a(n, e(n) !== pop)
    (1, 1, True, "strict_ne2"),        # 24: a(n, pop !== e(n))
    (1, 1, True, "mod"),               # 25: a(n, pop % e(n))
    (0, 2, True, "xor2"),              # 26: a(n, pop ^ pop)
    (1, 1, True, "add"),               # 27: a(n, e(n) + pop)
    (2, 0, False, "scope_chain_set"),  # 28: walk scope chain, set slot
    (4, 0, True, "call3"),             # 29: a(n, e(n)(e(n), e(n), e(n)))
    (0, 2, True, "strict_eq"),         # 30: a(n, pop === pop)
    (1, 1, True, "ne2"),               # 31: a(n, e(n) != pop)
    (1, 1, True, "bitand"),            # 32: a(n, pop & e(n))
    (1, 1, True, "mul2"),              # 33: a(n, pop * e(n))
    (1, 0, False, "save_try_state"),   # 34: save try state to scope
    (1, 0, True, "bitnot"),            # 35: a(n, ~e(n))
    (0, 0, True, "get_resolver0"),     # 36: a(n, i[1][0])
    (3, 0, False, "prop_set"),         # 37: e(n)[e(n)] = e(n)
    (2, 0, True, "bitor2"),            # 38: a(n, e(n) | e(n))
    (1, 0, True, "get_global"),        # 39: a(n, i[0][e(n)]) - global/runtime access
    (1, 1, True, "bitor3"),            # 40: a(n, e(n) | pop)
    (0, 2, True, "add2"),              # 41: a(n, pop + pop)
    (1, 0, False, "store_exception"),  # 42: scope.s[e(n)] = exception; clear
    (2, 0, True, "add3"),              # 43: a(n, e(n) + e(n))
    (1, 1, True, "gte"),               # 44: a(n, pop >= e(n))
    (2, 0, True, "delete"),            # 45: a(n, delete e(n)[e(n)])
    (0, 2, True, "in2"),               # 46: a(n, pop in pop)
    (1, 1, True, "ushr"),              # 47: a(n, pop >>> e(n))
    (1, 0, True, "lnot"),              # 48: a(n, !e(n))
    (0, 0, True, "empty_array"),       # 49: a(n, [])
    (0, 2, True, "mod2"),              # 50: a(n, pop % pop)
    (2, 0, True, "construct"),         # 51: a(n, new e(n)(...e(n)))
    (1, 0, True, "identity"),          # 52: a(n, e(n))
    (0, 2, True, "shl"),               # 53: a(n, pop << pop)
    (1, 0, True, "to_number"),         # 54: a(n, +e(n))
    (3, 0, False, "method_call"),      # 55: complex method invocation with frame
    (1, 0, True, "scope_chain_get"),   # 56: a(n, scope_chain[e(n)]) - READ from scope!
    (0, 2, True, "gt2"),               # 57: a(n, pop > pop)
    (1, 1, True, "add4"),              # 58: a(n, pop + e(n))
    (3, 0, True, "create_closure"),    # 59: create function/closure
    (1, 1, True, "div3"),              # 60: a(n, e(n) / pop)
    (0, 2, True, "sub2"),              # 61: a(n, pop - pop)
    (2, 0, True, "new_regexp"),        # 62: a(n, new RegExp(e(n), e(n)))
    (2, 0, True, "sub3"),              # 63: a(n, e(n) - e(n))
    (2, 0, True, "eq"),                # 64: a(n, e(n) == e(n))
    (1, 0, False, "call_native"),      # 65: native call r[0](n, e(n))
    (2, 0, True, "call1"),             # 66: a(n, e(n)(e(n)))
    (0, 0, False, "throw_undef"),      # 67: r[0](n, void 0) - throw
    (0, 2, True, "instanceof"),        # 68: a(n, pop instanceof pop)
    (1, 0, True, "call0"),             # 69: a(n, e(n)())
    (0, 0, True, "get_exception"),     # 70: a(n, n.n && n.n.Z)
    (0, 0, True, "get_resolver1"),     # 71: a(n, i[1][1])
    (0, 0, False, "halt"),             # 72: return null (stop execution)
    (1, 1, True, "strict_eq2"),        # 73: a(n, e(n) === pop)
    (1, 0, False, "jump"),             # 74: n.o[0] = e(n) (unconditional jump)
    (1, 1, True, "shl2"),              # 75: a(n, pop << e(n))
    (0, 2, True, "bitand2"),           # 76: a(n, pop & pop)
    (0, 2, True, "gte2"),              # 77: a(n, pop >= pop)
    (1, 1, True, "lte"),               # 78: a(n, pop <= e(n))
    (1, 1, True, "eq2"),               # 79: a(n, e(n) == pop)
    (0, 0, False, "clear_exception"),  # 80: n.n = void 0
    (0, 0, True, "get_window"),        # 81: a(n, n.o[1].h) - get global object
    (0, 2, True, "strict_ne3"),        # 82: a(n, pop !== pop)
    (3, 0, False, "cond_jump"),        # 83: e(n) ? n.o[0]=e(n) : e(n)
    (1, 1, True, "strict_eq3"),        # 84: a(n, pop === e(n))
    (1, 0, False, "call_native2"),     # 85: r[1](n, e(n))
    (3, 0, False, "cond_jump2"),       # 86: e(n) ? e(n) : n.o[0]=e(n)
]

assert len(HANDLERS) == 87, f"Expected 87 handlers, got {len(HANDLERS)}"

def decode_operand(program, ip, P_Q):
    if ip >= len(program):
        return None, ip, None
    a = program[ip]; ip += 1
    if a & 1:
        return f"{a>>1}", ip, a >> 1
    if a == 4:
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
            if len(s) > 60: s = s[:57] + "..."
            return f'"{s}"', ip, s
        return '"?"', ip, None
    if a == 16: return "false", ip, False
    if a == 20: return "true", ip, True
    if a == 26: return "void", ip, None
    return f"R{a>>5}", ip, a >> 5

def disasm(program, P_Q, start, end):
    ip = start
    lines = []
    while ip < end and ip < len(program):
        addr = ip
        raw_op = program[ip]; ip += 1
        
        if raw_op >= 87:
            # Not a valid opcode - shouldn't happen with correct disassembly
            lines.append(f"  {addr:6d}  ??? raw={raw_op}")
            continue
        
        e_reads, pop_reads, has_dest, name = HANDLERS[raw_op]
        
        # Read pop operands first (they come from bytecode via r[5](n) = j(n) = g(t,n.o,y,P))
        pops = []
        for _ in range(pop_reads):
            r, ip, raw = decode_operand(program, ip, P_Q)
            pops.append(r or "?")
        
        # Read e(n) operands
        ops = []
        for _ in range(e_reads):
            r, ip, raw = decode_operand(program, ip, P_Q)
            ops.append(r or "?")
        
        # Read dest register if handler stores
        dest = ""
        if has_dest:
            if ip < len(program):
                d = program[ip]; ip += 1
                dest = f" -> R{d >> 5}"
            else:
                dest = " -> ?"
        
        # Format
        all_args = []
        for p in pops:
            all_args.append(f"[pop]{p}")
        all_args.extend(ops)
        
        line = f"  {addr:6d}  {name:20s} {', '.join(all_args)}{dest}"
        
        # Annotations
        ann = ""
        full = " ".join(all_args)
        if '"vxn"' in full or "'vxn'" in full: ann = "  ; <<< VXN"
        elif '"exn"' in full: ann = "  ; <<< EXN"
        elif '"tp-v2-input"' in full: ann = "  ; <<< PoW SEED"
        elif '"sha256"' in full: ann = "  ; SHA-256"
        elif '"hmac"' in full: ann = "  ; HMAC"
        elif '"x-kpsdk-' in full: ann = "  ; KPSDK HDR"
        elif '"concat"' in full: ann = "  ; .concat()"
        elif '"slice"' in full: ann = "  ; .slice()"
        elif '"push"' in full: ann = "  ; .push()"
        elif '"answers"' in full: ann = "  ; PoW answers"
        elif '"workTime"' in full: ann = "  ; CD field"
        elif name == "scope_chain_get": ann = f"  ; READ scope[{ops[0] if ops else '?'}]"
        elif name == "scope_chain_set": ann = f"  ; WRITE scope[{ops[0]}] = {ops[1] if len(ops)>1 else '?'}"
        elif name == "scope_set": ann = f"  ; scope[{ops[0]}] = {ops[1] if len(ops)>1 else '?'}"
        elif name == "scope_decl": ann = f"  ; declare scope[{ops[0]}]"
        elif name == "jump": ann = f"  ; GOTO {ops[0]}"
        elif name == "cond_jump": ann = f"  ; IF {ops[0]} GOTO {ops[1]} ELSE skip"
        elif name == "cond_jump2": ann = f"  ; IF {ops[0]} skip ELSE GOTO {ops[2] if len(ops)>2 else '?'}"
        elif name == "halt": ann = "  ; === HALT ==="
        elif name == "set_loop_addr": ann = f"  ; loop_addr = {ops[0]}"
        elif name == "set_catch_addr": ann = f"  ; catch_addr = {ops[0]}"
        
        lines.append(line + ann)
    
    return lines


def main():
    work_dir = r"E:\kasada fully reverse\work"
    program, P_Q = load(work_dir)
    print(f"Program: {len(program)} ints, String table: {len(P_Q)} chars")
    
    # ======================================================================
    print()
    print("=" * 90)
    print("POW MINING FUNCTION: addr 46250 - 46650")
    print("=" * 90)
    for line in disasm(program, P_Q, 46250, 46650):
        print(line)
    
    # ======================================================================
    print()
    print("=" * 90)
    print("SCOPE 393 INIT: addr 5240 - 5300")
    print("=" * 90)
    for line in disasm(program, P_Q, 5240, 5300):
        print(line)
    
    # ======================================================================
    print()
    print("=" * 90)
    print("HMAC / x-kpsdk-h REGION: addr 22360 - 22470")
    print("=" * 90)
    for line in disasm(program, P_Q, 22360, 22470):
        print(line)
    
    # ======================================================================
    print()
    print("=" * 90)
    print("KPSDK HEADERS SETUP: addr 24960 - 25060")
    print("=" * 90)
    for line in disasm(program, P_Q, 24960, 25060):
        print(line)
    
    # ======================================================================
    # Save full disassembly
    print()
    print("Generating full disassembly...")
    lines = disasm(program, P_Q, 0, len(program))
    with open(f"{work_dir}/disasm_v3_full.txt", "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    print(f"Saved {len(lines)} lines to disasm_v3_full.txt")


if __name__ == "__main__":
    main()

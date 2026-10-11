"""
FULL KASADA REVERSE: Trace the complete PoW data flow
=====================================================
No sandbox. Pure static analysis of the bytecode.

Goal: Determine EXACTLY what value is concatenated with exn to form the SHA-256 input.
"""

import json

def load(work_dir):
    with open(f"{work_dir}/program_bytecode.json", "r") as f:
        data = json.load(f)
    program = data["ints"] if isinstance(data, dict) and "ints" in data else data
    with open(f"{work_dir}/string_table.txt", "r") as f:
        P_Q = f.read()
    return program, P_Q

TAGS = [4, 40, 30, 16, 20, 26]

# Correct handler info: (e_reads, pop_reads, has_dest, semantics)
HANDLER_INFO = [
    (2, 0, True, "prop_get"),      # 0
    (1, 0, False, "set_loop"),     # 1
    (1, 1, True, "div"),           # 2
    (1, 1, True, "xor"),           # 3
    (1, 0, False, "set_catch"),    # 4
    (1, 0, False, "scope_store_parent"),  # 5: scope.s[e(n)] = scope.a (parent value)
    (3, 0, True, "call2"),         # 6
    (1, 1, True, "neq"),           # 7
    (1, 1, True, "in"),            # 8
    (0, 2, True, "bitor"),         # 9
    (1, 0, False, "scope_decl"),   # 10
    (1, 0, True, "new_arr"),       # 11
    (0, 2, True, "lt"),            # 12
    (1, 1, True, "gt"),            # 13
    (1, 0, False, "scope_del"),    # 14
    (1, 1, True, "lt2"),           # 15
    (1, 0, True, "typeof"),        # 16
    (0, 2, True, "div2"),          # 17
    (1, 0, False, "try_catch"),    # 18
    (2, 0, False, "scope_set"),    # 19: scope.s[e(n)] = e(n)
    (0, 0, True, "new_obj"),       # 20
    (1, 1, True, "sub"),           # 21
    (0, 2, True, "mul"),           # 22
    (1, 1, True, "sneq"),          # 23
    (1, 1, True, "sneq2"),         # 24
    (1, 1, True, "mod"),           # 25
    (0, 2, True, "xor2"),          # 26
    (1, 1, True, "add"),           # 27
    (2, 0, False, "scope_write"),  # 28: scope chain write
    (4, 0, True, "call3"),         # 29
    (0, 2, True, "seq"),           # 30
    (1, 1, True, "neq2"),          # 31
    (1, 1, True, "band"),          # 32
    (1, 1, True, "mul2"),          # 33
    (1, 0, False, "save_try"),     # 34
    (1, 0, True, "bnot"),          # 35
    (0, 0, True, "get_promise"),   # 36
    (3, 0, False, "prop_set"),     # 37
    (2, 0, True, "bitor2"),        # 38
    (1, 0, True, "get_runtime"),   # 39
    (1, 1, True, "bitor3"),        # 40
    (0, 2, True, "add2"),          # 41
    (1, 0, False, "store_exc"),    # 42
    (2, 0, True, "add3"),          # 43
    (1, 1, True, "gte"),           # 44
    (2, 0, True, "del_prop"),      # 45
    (0, 2, True, "in2"),           # 46
    (1, 1, True, "ushr"),          # 47
    (1, 0, True, "lnot"),          # 48
    (0, 0, True, "new_arr2"),      # 49
    (0, 2, True, "mod2"),          # 50
    (2, 0, True, "construct"),     # 51
    (1, 0, True, "identity"),      # 52
    (0, 2, True, "shl"),           # 53
    (1, 0, True, "uplus"),         # 54
    (3, 0, True, "method_call"),   # 55
    (0, 0, False, "yield"),        # 56
    (1, 0, True, "scope_read"),    # 57: read from scope chain into register
    (0, 2, True, "gt2"),           # 58
    (1, 1, True, "add4"),          # 59
    (3, 0, False, "call_try"),     # 60
    (0, 0, True, "proxy_get"),     # 61
    (1, 1, True, "div3"),          # 62
    (0, 2, True, "sub2"),          # 63
    (2, 0, True, "new_regex"),     # 64
    (2, 0, True, "sub3"),          # 65
    (2, 0, True, "eq"),            # 66
    (1, 0, False, "throw"),        # 67
    (2, 0, True, "call1"),         # 68
    (0, 0, False, "throw_undef"),  # 69
    (0, 2, True, "instanceof"),    # 70
    (1, 0, True, "call0"),         # 71
    (0, 0, True, "get_exc"),       # 72
    (0, 0, True, "get_resolve"),   # 73
    (0, 0, False, "halt"),         # 74
    (1, 1, True, "seq2"),          # 75
    (1, 0, False, "jump"),         # 76
    (1, 1, True, "shl2"),          # 77
    (0, 2, True, "band2"),         # 78
    (0, 2, True, "gte2"),          # 79
    (1, 1, True, "lte"),           # 80
    (1, 1, True, "eq2"),           # 81
    (0, 0, False, "clear_exc"),    # 82
    (0, 0, True, "get_window"),    # 83
    (0, 2, True, "sneq3"),         # 84
    (3, 0, False, "cond_jump"),    # 85
    (1, 1, True, "seq3"),          # 86
    (1, 0, False, "catch"),        # 87
    (3, 0, False, "cond"),         # 88
]

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
            return f'"{s}"', ip, s
        return '"?"', ip, None
    if a == 16: return "false", ip, False
    if a == 20: return "true", ip, True
    if a == 26: return "void", ip, None
    return f"R{a>>5}", ip, a >> 5

def disasm_range(program, P_Q, start, end):
    """Disassemble a range with full detail"""
    ip = start
    results = []
    while ip < end and ip < len(program):
        addr = ip
        op = program[ip]; ip += 1
        if op >= len(HANDLER_INFO):
            results.append((addr, op, "DATA", [], [], None))
            continue
        e_reads, pop_reads, has_dest, sem = HANDLER_INFO[op]
        e_ops = []
        for _ in range(e_reads):
            r, ip, raw = decode_operand(program, ip, P_Q)
            e_ops.append((r, raw))
        pop_ops = []
        for _ in range(pop_reads):
            r, ip, raw = decode_operand(program, ip, P_Q)
            pop_ops.append((r, raw))
        dest = None
        if has_dest:
            if ip < len(program):
                dest = program[ip] >> 5; ip += 1
        results.append((addr, op, sem, e_ops, pop_ops, dest))
    return results

def format_instr(addr, op, sem, e_ops, pop_ops, dest):
    if sem == "DATA":
        return f"{addr:6d}  DATA {op}"
    parts = []
    for r, raw in pop_ops:
        parts.append(f"pop:{r}")
    for r, raw in e_ops:
        parts.append(r or "?")
    d = f" -> R{dest}" if dest is not None else ""
    return f"{addr:6d}  OP_{op:2d}/{sem}({', '.join(parts)}){d}"

def main():
    work_dir = r"E:\kasada fully reverse\work"
    program, P_Q = load(work_dir)
    print(f"Program: {len(program)} ints")
    print()
    
    # ======================================================================
    # THE KEY REGION: PoW mining function (46260-46600)
    # ======================================================================
    print("=" * 80)
    print("MINING FUNCTION: addr 46250-46600")
    print("=" * 80)
    print()
    
    instrs = disasm_range(program, P_Q, 46250, 46600)
    for addr, op, sem, e_ops, pop_ops, dest in instrs:
        print(format_instr(addr, op, sem, e_ops, pop_ops, dest))
    
    # ======================================================================
    # ANALYSIS: Trace the concat operation
    # ======================================================================
    print()
    print("=" * 80)
    print("ANALYSIS: What is concatenated with exn?")
    print("=" * 80)
    print()
    
    # At 46350: OP_0(R4, "exn") -> R5   ; R5 = state.exn
    # At 46356: OP_28(1969, R5)          ; scope[1969] = R5 (exn string)
    # At 46362: OP_0(R4, "concat") -> R6 ; R6 = exn.concat (method)
    # At 46368: OP_11(1) -> R7           ; R7 = new Array(1) (args array)
    # 
    # Then OP_56 (yield) happens... the concat args are built in sub-frames
    # 
    # The structure is:
    # state = scope[398] = {exn: "tp-v2-input", vxn: R5}
    # exn_value = state.exn  (string)
    # concat_result = exn_value.concat(???)
    # hash = sha256(concat_result)
    
    # The vxn value in the state object (scope[398]) is what gets concatenated.
    # At initialization (46316): state.vxn = R5 = {qdw:10, xqn:2}
    # 
    # BUT WAIT: Look at the pattern more carefully.
    # The PoW function is actually a GENERATOR (uses OP_56 yield extensively)
    # The mining loop is a sub-function that gets called with arguments.
    #
    # Let's look at addr 46334-46345 where the sub-function scope is set up:
    # 46334  OP_5(1965)        ; scope[1965] = parent scope value
    # 46336  OP_19(1966, R4)   ; scope[1966] = R4
    # 46339  OP_19(1967, R5)   ; scope[1967] = R5
    # 46342  OP_19(1968, R6)   ; scope[1968] = R6
    # 46345  OP_10(1969)       ; scope[1969] = undefined (will be set)
    #
    # The parent scope (via OP_5) gives access to scope[393-398]
    # Scope 1967 = R5 which at that point could be the vxn secret!
    
    print("Tracing the generator/sub-function setup:")
    print()
    print("At addr 46303-46322 (PoW state initialization):")
    print("  46303: R4 = {}  (new object)")
    print("  46305: R4.exn = 'tp-v2-input'")
    print("  46316: R4.vxn = R5")
    print("  46322: scope[398] = R4  (store state object)")
    print()
    print("R5 at addr 46316 = the object from addr 46272:")
    print("  46272: R5 = {} (new object)")
    print("  46274: R5.qdw = 10")
    print("  46280: R5.xqn = 2")
    print("  46286: scope[393] = R5")
    print()
    print("SO vxn is initially = {qdw:10, xqn:2}")
    print("When concatenated as string: '[object Object]'")
    print()
    print("BUT this can't be right for PoW! The hash would be deterministic!")
    print("seed = 'tp-v2-input' + '[object Object]' = always the same!")
    print()
    
    # ======================================================================
    # CRITICAL INSIGHT: Look at what R5 REALLY is at addr 46316
    # ======================================================================
    print("=" * 80)
    print("CRITICAL: Re-examining what R5 is at addr 46316")
    print("=" * 80)
    print()
    
    # The issue: Between addr 46286 and 46316, does R5 change?
    # Let's look at the EXACT bytes and correct disassembly
    
    print("Raw bytecode 46286-46320:")
    for i in range(46286, 46320):
        print(f"  [{i}] = {program[i]}")
    
    print()
    print("Re-disassembling byte by byte:")
    instrs = disasm_range(program, P_Q, 46286, 46325)
    for addr, op, sem, e_ops, pop_ops, dest in instrs:
        line = format_instr(addr, op, sem, e_ops, pop_ops, dest)
        # Also show raw bytes
        if sem != "DATA":
            e_r, pop_r, has_d, _ = HANDLER_INFO[op]
            end_ip = addr + 1
            # Count bytes
            raw_bytes = [program[addr]]
            print(f"{line}")
        else:
            print(f"{line}")
    
    # ======================================================================
    # Let me look at the OP_56 (yield) at 46313 and what happens after
    # ======================================================================
    print()
    print("=" * 80)
    print("YIELD ANALYSIS: The generator pattern")
    print("=" * 80)
    print()
    
    # OP_56 is "yield" - it returns from the current handler call
    # In generator pattern, the function pauses here and resumes later
    # After yield, the next call resumes with a new value
    # 
    # Structure:
    # 46305: R4.exn = "tp-v2-input"
    # 46313: yield  (pause - returns from sub-frame)
    # 46314: DATA 787 = (393 << 1) | 1 = 787 -> this is small int 393
    # 46315: DATA 160 = register ref: 160 >> 5 = 5 -> R5
    # 46316: OP_37(R4, "vxn", R5)
    
    # The DATA 787 and DATA 160 between yield and OP_37...
    # These are NOT consumed by OP_56 (which has 0 operands)
    # And NOT consumed by OP_37 (which reads 3 operands from e(n))
    
    # WAIT. Let me re-check the OP_56 handler:
    # OP_56: (0, 0, False, "yield") - 0 e_reads, 0 pop_reads, no dest
    # Total bytes consumed = 1 (just the opcode)
    
    # So after OP_56 at addr 46313 (byte [46313] = 56):
    # Next byte is [46314] = 787 which is NOT a valid opcode (>= 89)
    # In linear sweep it's DATA
    
    # But in the ACTUAL execution, after yield returns, the PC is set to 
    # somewhere else! The generator resumes at a DIFFERENT address!
    
    # The yield/resume pattern means:
    # 1. The function yields (OP_56) - execution goes BACK to caller
    # 2. Later, when resumed, PC is set to the RESUME address
    # 3. The DATA 787 and 160 might be consumed by the RESUME logic
    
    # Actually looking at the OP_56 handler again:
    # function(){return arguments}.apply(void 0,_)
    # This is weird... Let me look at it differently.
    
    # ACTUALLY - OP_56 is at index 56 in the handler array.
    # Let me extract it directly.
    
    print("Looking at what's BETWEEN the yield and the next real instruction...")
    print()
    print(f"  [46313] = {program[46313]} (opcode 56 = yield)")  
    print(f"  [46314] = {program[46314]} (= {program[46314] >> 1} as small int, or R{program[46314]>>5} as reg)")
    print(f"  [46315] = {program[46315]} (= {program[46315] >> 1} as small int, or R{program[46315]>>5} as reg)")
    print(f"  [46316] = {program[46316]} (opcode 37 = prop_set)")
    
    # 787 is odd -> small int 393
    # 160 is even, not a tag -> register R5 (160>>5 = 5)
    # 
    # These two values (393, R5) look like operands for OP_19 or OP_28
    # But there's no opcode before them!
    #
    # UNLESS the disassembler is off by one here.
    # Let me check: what if OP_56 at addr 46313 is NOT the actual instruction?
    
    # Let me trace from a known good anchor and re-disassemble:
    print()
    print("Re-tracing from addr 46303 (OP_20):")
    instrs = disasm_range(program, P_Q, 46303, 46330)
    for addr, op, sem, e_ops, pop_ops, dest in instrs:
        print(f"  {format_instr(addr, op, sem, e_ops, pop_ops, dest)}")
        if sem != "DATA":
            e_r, pop_r, has_d, _ = HANDLER_INFO[op]
            consumed = 1 + e_r + pop_r + (1 if has_d else 0)
            # But operands have variable length! Need to track actual consumption
    
    # ======================================================================
    # DEEPER: Let me look at what scope[398] REALLY contains over time
    # ======================================================================
    print()
    print("=" * 80)
    print("SCOPE[398] STATE OBJECT: Where it's written")
    print("=" * 80)
    print()
    
    # Find all OP_28 writes to scope 398
    # OP_28 encoded as: [28, operand1, operand2, v(n)] where v(n) doesn't consume bytecode
    # operand1 for slot 398 would be (398 << 1) | 1 = 797 as raw byte (odd = small int)
    
    print("Searching for scope[398] writes (OP_28 with slot 398)...")
    writes_398 = []
    ip = 0
    while ip < len(program):
        if program[ip] == 28 and ip + 1 < len(program):
            # Check if first operand is 398 (encoded as 797)
            next_byte = program[ip + 1]
            if next_byte & 1 and (next_byte >> 1) == 398:
                # Decode second operand
                _, next_ip, _ = decode_operand(program, ip + 1, P_Q)
                r2, _, raw2 = decode_operand(program, next_ip, P_Q)
                writes_398.append((ip, r2, raw2))
        ip += 1
    
    print(f"Found {len(writes_398)} writes to scope[398]:")
    for addr, val_repr, raw in writes_398:
        print(f"  addr {addr}: scope[398] = {val_repr}")
    
    # ======================================================================
    # LOOK AT THE FUNCTION THAT SETS UP THE POW 
    # ======================================================================
    print()
    print("=" * 80)
    print("FUNCTION ENTRY: What calls the PoW miner?")  
    print("=" * 80)
    print()
    
    # The OP_59 at addr 46325 creates a function reference
    # OP_59: a(n, pop + e(n)) -> add pop to operand
    # Actually OP_59 is "add4": a(n, pop + e(n))
    # Let me look at the broader context - what happens BEFORE 46250
    
    instrs = disasm_range(program, P_Q, 46200, 46260)
    for addr, op, sem, e_ops, pop_ops, dest in instrs:
        print(f"  {format_instr(addr, op, sem, e_ops, pop_ops, dest)}")

    # ======================================================================
    # LOOK AT SCOPE[393] writes - where does the REAL vxn get stored?
    # ======================================================================
    print()
    print("=" * 80)
    print("ALL SCOPE[393] WRITES")
    print("=" * 80)
    print()
    
    writes_393 = []
    ip = 0
    while ip < len(program):
        # Check OP_28 (scope chain write)
        if program[ip] == 28 and ip + 1 < len(program):
            next_byte = program[ip + 1]
            if next_byte & 1 and (next_byte >> 1) == 393:
                _, next_ip, _ = decode_operand(program, ip + 1, P_Q)
                r2, _, raw2 = decode_operand(program, next_ip, P_Q)
                writes_393.append((ip, 28, r2))
        # Check OP_19 (scope set)
        if program[ip] == 19 and ip + 1 < len(program):
            next_byte = program[ip + 1]
            if next_byte & 1 and (next_byte >> 1) == 393:
                _, next_ip, _ = decode_operand(program, ip + 1, P_Q)
                r2, _, raw2 = decode_operand(program, next_ip, P_Q)
                writes_393.append((ip, 19, r2))
        ip += 1
    
    print(f"Found {len(writes_393)} writes to scope[393]:")
    for addr, op, val_repr in writes_393:
        print(f"  addr {addr}: OP_{op} scope[393] = {val_repr}")
        # Disassemble surrounding context
        context = disasm_range(program, P_Q, max(0, addr-10), addr+10)
        for ca, co, cs, ce, cp, cd in context:
            marker = " <<<" if ca == addr else ""
            print(f"    {format_instr(ca, co, cs, ce, cp, cd)}{marker}")
        print()


if __name__ == "__main__":
    main()

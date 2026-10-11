"""
Trace vxn origin: find all writes to scope slot 393
and the broader challenge/token processing logic.
"""

import json

def load_program(work_dir):
    with open(f"{work_dir}/program_bytecode.json", "r") as f:
        data = json.load(f)
    return data["ints"] if isinstance(data, dict) and "ints" in data else data

def load_string_table(work_dir):
    with open(f"{work_dir}/string_table.txt", "r") as f:
        return f.read()

TAGS = [4, 40, 30, 16, 20, 26]
ARITIES = [
    2,1,1,1,1,2,3,1,1,0,2,1,0,1,2,1,1,0,2,3,0,1,0,1,1,1,0,1,3,4,0,1,1,1,2,1,0,3,2,1,1,0,2,2,1,2,0,1,1,0,0,2,1,0,1,3,0,2,0,1,4,0,1,0,2,2,2,1,2,0,0,1,0,0,0,1,1,1,0,0,1,1,0,0,0,3,1,1,3
]

def decode_operand(program, ip, P_Q):
    if ip >= len(program):
        return None, ip, None
    a = program[ip]; ip += 1
    if a & 1:
        return str(a >> 1), ip, a >> 1
    if a == 4:  # double
        if ip + 1 < len(program):
            ip += 2
        return "DOUBLE", ip, None
    if a == 40: return "null", ip, None
    if a == 30:  # string
        if ip + 1 < len(program):
            length = program[ip]; offset = program[ip + 1]; ip += 2
            s = P_Q[offset:offset + length] if offset + length <= len(P_Q) else "???"
            return f'"{s}"', ip, s
        return '"?"', ip, None
    if a == 16: return "false", ip, False
    if a == 20: return "true", ip, True
    if a == 26: return "void", ip, None
    reg = a >> 5
    return f"R{reg}", ip, None

def main():
    work_dir = r"E:\kasada fully reverse\work"
    program = load_program(work_dir)
    P_Q = load_string_table(work_dir)
    
    print("=" * 70)
    print("TRACING VXN ORIGIN: Scope slot 393 writes")
    print("=" * 70)
    print()
    
    # OP_19 (scope store) has arity 3: scope_slot, value, ???
    # OP_5 (scope store) has arity 2: scope_slot, ???
    # OP_10 (declare scope var) has arity 2: scope_slot, value
    
    # Search for OP_19 with first operand = 787 (which is (393 << 1) | 1 = 787)
    # Actually in the VM, scope slots are stored via different mechanisms
    # Let's look at the raw operand encoding: 393 as a small int = (393 << 1) | 1 = 787
    
    # OP_19(slot, value, ...) - scope store
    # OP_5(slot, ...) - scope store  
    # OP_10(slot, value) - declare scope var
    
    # Looking at addr 46316: OP_37(R4 "vxn" R5)
    # This sets obj.vxn = R5 where obj is R4
    # R4 was set at addr 46305: OP_37(R4 "exn" "tp-v2-input")
    # Actually R4 is the same object being built with properties
    
    # The critical question is: what is R5 at addr 46316?
    # From the trace: addr 46286: OP_28(393 R5 24)
    # OP_28 has arity 3 and does scope chain lookup
    # This reads scope variable 393 into R5 with depth/context 24
    
    # So we need to find where scope slot 393 is WRITTEN
    # Scope writes use OP_19, OP_5, or OP_10
    
    print("Looking for writes to scope slot 393...")
    print("  In bytecode, 393 as odd small int = 787")
    print()
    
    # OP_19 (arity 3): first operand is the scope slot
    # OP_5 (arity 2): first operand is the scope slot 
    # OP_10 (arity 2): first operand is the scope slot
    
    scope_writes_393 = []
    
    ip = 0
    while ip < len(program):
        op = program[ip]
        if op >= len(ARITIES):
            ip += 1
            continue
        
        start = ip
        ip += 1
        arity = ARITIES[op]
        
        # For scope-writing opcodes, check if first operand is 393
        if op in (19, 5, 10):
            # Read first operand
            if ip < len(program):
                first_raw = program[ip]
                # Check if it's small int 393 (encoded as 787)
                if first_raw & 1 and (first_raw >> 1) == 393:
                    # Decode all operands for display
                    save_ip = ip
                    ops = []
                    for _ in range(arity):
                        repr_str, ip, raw_val = decode_operand(program, ip, P_Q)
                        if repr_str is None: break
                        ops.append(repr_str)
                    scope_writes_393.append((start, op, ops))
                    ip = save_ip  # reset
            
        # Skip operands
        ip = start + 1
        for _ in range(arity):
            if ip >= len(program): break
            a = program[ip]; ip += 1
            if a & 1: pass
            elif a == 4: ip += 2
            elif a == 40: pass
            elif a == 30: ip += 2
            elif a == 16: pass
            elif a == 20: pass
            elif a == 26: pass
            else: pass  # register
    
    print(f"Found {len(scope_writes_393)} writes to scope slot 393:")
    for addr, op, ops in scope_writes_393:
        print(f"  addr {addr}: OP_{op}({' '.join(ops)})")
    
    # Also search for OP_28 reads from slot 393
    print()
    print("Looking for OP_28 reads from scope slot 393...")
    scope_reads_393 = []
    
    ip = 0
    while ip < len(program):
        op = program[ip]
        if op >= len(ARITIES):
            ip += 1
            continue
        start = ip
        ip += 1
        arity = ARITIES[op]
        
        if op == 28:  # scope chain lookup
            if ip < len(program):
                first_raw = program[ip]
                if first_raw & 1 and (first_raw >> 1) == 393:
                    save_ip = ip
                    ops = []
                    for _ in range(arity):
                        repr_str, ip, raw_val = decode_operand(program, ip, P_Q)
                        if repr_str is None: break
                        ops.append(repr_str)
                    scope_reads_393.append((start, ops))
                    ip = save_ip
        
        ip = start + 1
        for _ in range(arity):
            if ip >= len(program): break
            a = program[ip]; ip += 1
            if a & 1: pass
            elif a == 4: ip += 2
            elif a == 40: pass
            elif a == 30: ip += 2
            elif a == 16: pass
            elif a == 20: pass
            elif a == 26: pass
    
    print(f"Found {len(scope_reads_393)} reads from scope slot 393:")
    for addr, ops in scope_reads_393:
        print(f"  addr {addr}: OP_28({' '.join(ops)})")
    
    # Now let's look at what happens around the vxn update at 46469
    # addr 46469: OP_37(R4 "vxn" R8)
    # R8 is set at addr 46443: OP_52(R8)
    # OP_52 is identity - so what's the previous thing that produced R8?
    # Looking at the region 46430-46469:
    # 46440 DATA 192
    # 46441 DATA 224
    # 46442 DATA 256
    # 46443 OP_52(R8)
    # This means R8 receives whatever the store function (F) writes
    # The DATA entries before 46443 are the values from the evaluation stack
    
    print()
    print("=" * 70)
    print("TRACING AROUND VXN UPDATE (addr 46469)")
    print("=" * 70)
    print()
    
    # Disassemble the region 46400-46480 in detail
    ip = 46400
    while ip < min(46500, len(program)):
        op = program[ip]
        if op >= len(ARITIES):
            print(f"  {ip:6d}  DATA {op}")
            ip += 1
            continue
        start = ip; ip += 1
        ops = []
        for _ in range(ARITIES[op]):
            repr_str, ip, _ = decode_operand(program, ip, P_Q)
            if repr_str is None: break
            ops.append(repr_str)
        ann = ""
        if "vxn" in " ".join(ops): ann = " <<< VXN"
        if "exn" in " ".join(ops): ann = " <<< EXN"
        print(f"  {start:6d}  OP_{op:2d}({' '.join(ops)}){ann}")
    
    # Now look for where the CT/challenge response is processed
    # The key insight is that vxn is from scope 393, which must be
    # set earlier during the handshake processing
    
    print()
    print("=" * 70)
    print("LOOKING FOR SCOPE 393 INITIALIZATION")
    print("=" * 70)
    print()
    
    # If scope 393 writes are found, let's trace what value they store
    # The value in OP_19(393, value, ...) tells us what goes into slot 393
    
    # Also let's look at the broader PoW function setup (addr ~46259-46300)
    # This is where the PoW parameters object is created:
    # 46272 OP_20() - new object
    # 46274 OP_37(R5 "qdw" 10) - obj.qdw = 10
    # 46280 OP_37(R5 "xqn" 2) - obj.xqn = 2
    # 46286 OP_28(393 R5 24) - R5 = scope[393] (THIS IS VXN!)
    
    # Wait - looking again at the operand decoding for OP_28(393 R5 24):
    # OP_28 has arity 3: (slot_idx, dest_register, depth?)
    # Actually let's re-examine - does OP_28 read TO R5 or FROM R5?
    
    # From the opcode table:
    # OP_28 (scope chain lookup): for(var i=e(n), r=e(n), o=v(n); o; o=o.m) ...
    # It reads 3 operands: i (the slot index), r (??), and uses v(n) for scope
    # Actually looking at the handler code:
    # function(n,e,a,v){var i=e(n),r=e(n),o=v(n); ...}
    # It reads: first operand (slot index), second operand (value/register), third operand
    # And it stores: r.s[i] = o  (writes TO the scope)
    
    # Wait no - this is confusing. Let me re-check the handler code from the analysis:
    # OP_28: scope chain lookup - "Walk scope chain"
    # From vm_section.js, OP_28 is handler index 28 in the Proxy array.
    
    # Actually from the guide: OP_28 has arity 3 and does "Scope chain lookup"
    # The semantics are: walk the scope chain to find and store a value
    # Looking at the disasm: OP_28(393 R5 24)
    # This means: scope[393] = R5 (with some depth context)
    # OR: R5 = scope[393] (reading from scope)
    
    # The confusion is whether OP_28 is a READ or WRITE operation
    # Let's check: in the trace output, at addr 46316: OP_37(R4 "vxn" R5)
    # This uses R5 as the VALUE to set, meaning R5 must contain the vxn value
    # If OP_28(393 R5 24) at addr 46286 READS scope[393] INTO R5, 
    # then vxn = scope[393] makes sense
    
    # But the handler code from vm_section.js shows:
    # function(n,e,a,v){var i=e(n),r=e(n),o=v(n);...}
    # Where e(n) reads an operand. So:
    #   i = 393 (first operand - slot index)
    #   r = R5 (second operand - register/value)
    #   o = v(n) (third operand - scope walk with v function)
    # Then the handler does: scope.s[i] = r (WRITE)
    # Which means: scope[393] = R5
    
    # WAIT - that means OP_28(393 R5 24) WRITES R5 to scope slot 393!
    # Then scope slot 393 gets R5, which at that point = the object we just built
    # (qdw=10, xqn=2)
    
    # But then at 46316: OP_37(R4 "vxn" R5) - this sets R4.vxn = R5
    # R5 at 46316 is the SAME R5 that was just stored to scope 393?
    # No wait, there's no instruction between 46286 and 46316 that changes R5
    # (only OP_28(394 R4 R0) at 46291 changes R4)
    
    # Actually... let me re-read the handler. There are two different scope ops:
    # Some scope ops READ (get from scope into register)
    # Some scope ops WRITE (put from register into scope)
    
    # Let me look at the actual handler index 28 from the Proxy array in vm_section.js:
    
    print("Let me look at what OP_28 actually does by examining the raw handler...")
    print()
    
    # The critical question is the semantics of OP_28
    # From KASADA_COMPLETE_REVERSING_GUIDE.md Section 10:
    # "OP_28: scope chain lookup
    #  function(n,e,a,v) {
    #    for (var i=e(n), r=e(n), o=v(n); o; o=o.m) {
    #      if (i in o.s) { o.s[i] = r; return; }
    #    }
    #  }"
    # This WRITES r to scope.s[i] - it's a WRITE operation!
    
    # So OP_28(393, R5, 24) means: scope[393] = R5 (with scope depth context 24)
    # And at addr 46286, R5 was set to the object with qdw=10, xqn=2
    # That's the PoW parameters object, not vxn!
    
    # Then at addr 46316: OP_37(R4 "vxn" R5) - this sets R4.vxn = R5
    # Where did R5 change between addr 46286 and 46316?
    
    # Let's look more carefully at the instructions between 46286 and 46316:
    print("Instructions between 46286 and 46316:")
    ip = 46286
    while ip <= 46320:
        op = program[ip]
        if op >= len(ARITIES):
            print(f"  {ip:6d}  DATA {op}")
            ip += 1
            continue
        start = ip; ip += 1
        ops = []
        for _ in range(ARITIES[op]):
            repr_str, ip, _ = decode_operand(program, ip, P_Q)
            if repr_str is None: break
            ops.append(repr_str)
        print(f"  {start:6d}  OP_{op:2d}({' '.join(ops)})")
    
    print()
    print("KEY INSIGHT: Let's re-examine the semantics of OP_28")
    print()
    print("From guide: OP_28 scope chain lookup - WRITES value to scope")
    print("  OP_28(393 R5 24) at addr 46286: scope[393] = R5")
    print("  At this point R5 = the {qdw:10, xqn:2} object")
    print()
    print("  But then at addr 46316: OP_37(R4 'vxn' R5)")
    print("  This sets R4.vxn = R5")
    print("  R5 has NOT changed between 46286 and 46316!")
    print("  (addr 46291 only changes R4)")
    print()
    print("  CONCLUSION: vxn = R5 = the {qdw:10, xqn:2} object???")
    print("  That can't be right... ")
    print()
    print("  ALTERNATIVE: Maybe OP_28 is READING not WRITING!")
    print("  If OP_28(slot, register, depth) means register = scope[slot]")
    print("  Then R5 = scope[393] and vxn comes from scope slot 393")
    print()
    
    # Let's verify by looking at other OP_28 usage patterns
    # At addr 46291: OP_28(394 R4 R0)
    # If this is a READ: R4 = scope[394]
    # Then R4 gets overwritten before being used in OP_37(R4 "exn" ...)
    # That makes sense - R4 is loaded with an object that then gets properties set on it
    
    # At addr 46322: OP_28(398 R4 29) 
    # If READ: R4 = scope[398] - but R4 was just used as the property-set target
    # This could be storing the completed PoW params object
    
    # Actually, looking at the guide AGAIN more carefully:
    # Section 8: "OP_28 | 3 | Scope chain lookup | Walk scope chain"
    # Section 10: The scope chain walk code shows it WRITES
    
    # But there's also OP_57: "Scope chain read | Walk scope chain for var"
    # OP_57 has arity 2 and does reading
    
    # Let me look at how OP_28 is used elsewhere to determine if it reads or writes
    # Example: addr 46356: OP_28(1969 R5 R1)
    # This is inside the mining loop where exn is loaded
    # If it's a READ: R5 = scope[1969] - R5 is then used with .concat()
    # If it's a WRITE: scope[1969] = R5 - but R5 hasn't been set yet
    
    # Looking at addr 46350: OP_0(R4 "exn") - loads R4.exn property
    # Then addr 46356: OP_28(1969 R5 R1)
    # If OP_28 WRITES: scope[1969] = R5 (but R5 undefined here)
    # If OP_28 READS: R5 = scope[1969] (R5 gets a value to use with concat)
    
    # Then addr 46362: OP_0(R4 "concat") - gets concat method
    # This suggests R4 has the "exn" string (from OP_0), and we need something to concat with
    # R5 would be that something - supporting OP_28 as a READ
    
    # ACTUALLY - let me re-read the guide's OP_28 code more carefully:
    # "function(n,e,a,v){var i=e(n), r=e(n), o=v(n); ...}"
    # The handler has params (n, e, a, v, i, r) but uses only (n, e, a, v)
    # That means it uses: e (read_operand) and v (read_variable)
    # It reads 2 operands with e(n) and 1 with v(n)
    # The function a() is store_result
    
    # Wait - the handler calls a() at some point? Let me check...
    # From the guide: "for(var i=e(n), r=e(n), o=v(n); o; o=o.m) { if(i in o.s) { o.s[i]=r; return } }"
    # This is a WRITE: it searches the scope chain for slot i and sets it to r
    # But wait - it doesn't call a(n, value) to store a result!
    # So OP_28 is purely a WRITE to scope, not a register store
    
    # But then how does the disasm show "OP_28(393 R5 24)"?
    # 393 = first operand (slot index)
    # R5 = second operand (value to store)
    # 24 = third operand (used with v(n) function - scope depth?)
    
    # If OP_28 WRITES scope[393] = R5, then at addr 46286:
    # We're storing R5 (the PoW params object) into scope slot 393
    # And then at addr 46316: OP_37(R4 "vxn" R5)
    # R5 still holds the PoW params object
    # So vxn would be {qdw:10, xqn:2}... that makes no sense for a hash input!
    
    # WAIT. Let me re-read the disassembler output more carefully.
    # The issue is that the operand decoder might be wrong about what's e(n) vs v(n)
    # The arity for OP_28 is listed as 3, but the handler uses 2 e(n) + 1 v(n)
    # Our disassembler treats all 3 as e(n) (standard operand decode)
    # But v(n) is the "read_variable" function which reads from scope differently!
    
    # This means the third "operand" of OP_28 may not be decoded the same way
    # The v(n) call reads a variable from the scope chain
    
    # ACTUALLY - looking at the handler table more carefully from vm_section.js:
    # Let me re-examine what the actual handler does and how to interpret operands
    
    print("NEED TO RE-EXAMINE: OP_28 handler uses v(n) for 3rd operand")
    print("v(n) is the scope variable reader, not the standard operand decoder")
    print("This means the 3rd decoded value might not be what we think")
    print()
    print("The critical path to solving vxn:")
    print("  1. R5 at addr 46316 contains the vxn value")
    print("  2. Either OP_28 at 46286 READS scope[393] into R5")
    print("     OR R5 is set by something else between 46280 and 46316")
    print("  3. Need dynamic instrumentation to resolve this definitively")


if __name__ == "__main__":
    main()

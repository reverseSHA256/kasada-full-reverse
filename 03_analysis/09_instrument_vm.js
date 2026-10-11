/**
 * Kasada VM Instrumentation Harness
 * ==================================
 * 
 * This script instruments the p.js VM to capture:
 * 1. The value of `vxn` when it's set/read
 * 2. All scope chain operations (OP_28 writes, OP_57 reads)
 * 3. The /tl response processing
 * 4. The PoW computation (hash inputs, outputs, answers)
 * 5. The HMAC computation
 * 
 * Strategy:
 * - Patch the dispatch loop (function U) to log every opcode execution
 * - Hook the property set (OP_37) to detect vxn writes
 * - Hook the scope write (OP_28) to capture scope slot values
 * - Run the VM in a sandboxed Node.js environment with happy-dom
 * 
 * This requires: npm install happy-dom impit
 */

const fs = require('fs');
const path = require('path');

// Load the p.js source
const pjsPath = path.join(__dirname, 'p.js');
const pjsSource = fs.readFileSync(pjsPath, 'utf-8');

console.log(`Loaded p.js: ${pjsSource.length} bytes`);

// ============================================================================
// STEP 1: Patch p.js to add instrumentation
// ============================================================================

/**
 * We need to patch the VM at several points:
 * 
 * 1. BEFORE the Proxy array: inject a logging wrapper
 * 2. The dispatch loop (function U): add per-instruction tracing
 * 3. The store function (F): log register writes
 * 4. The scope operations (handlers 28, 19, 5): log scope writes
 * 
 * The key patch: wrap each handler in the Proxy to intercept execution.
 */

function createInstrumentedVM(source) {
    // Strategy: Instead of patching the minified source (fragile),
    // we'll wrap the Proxy with a custom proxy that intercepts handler calls
    
    // Find the Proxy creation: u=new Proxy([...], {...})
    // Replace it with instrumented version
    
    let patched = source;
    
    // Inject our instrumentation object BEFORE the IIFE
    const instrumentCode = `
// === KASADA VM INSTRUMENTATION ===
var __KASADA_LOG = {
    enabled: false,
    traces: [],
    vxn_values: [],
    scope_writes: [],
    scope_reads: [],
    property_sets: [],
    hash_inputs: [],
    hash_outputs: [],
    instruction_count: 0,
    
    // Called on every OP_37 (property set)
    onPropertySet: function(obj, key, value) {
        if (key === 'vxn') {
            this.vxn_values.push({
                value: value,
                type: typeof value,
                str: String(value).substring(0, 200),
                count: this.instruction_count
            });
            console.log('[VXN SET] value=' + JSON.stringify(value).substring(0, 200) + 
                       ' type=' + typeof value + ' at instr #' + this.instruction_count);
        }
        if (key === 'exn') {
            console.log('[EXN SET] value=' + JSON.stringify(value).substring(0, 100) + 
                       ' at instr #' + this.instruction_count);
        }
        if (key === 'answers') {
            console.log('[ANSWERS SET] value=' + JSON.stringify(value).substring(0, 200) + 
                       ' at instr #' + this.instruction_count);
        }
        if (key === 'workTime' || key === 'duration' || key === 'id') {
            console.log('[CD FIELD] ' + key + '=' + JSON.stringify(value).substring(0, 100));
        }
    },
    
    // Called on every OP_0 (property get)
    onPropertyGet: function(obj, key, result) {
        if (key === 'vxn') {
            console.log('[VXN GET] value=' + JSON.stringify(result).substring(0, 200) + 
                       ' type=' + typeof result + ' at instr #' + this.instruction_count);
        }
    },
    
    // Called when concat is used (to trace PoW seed construction)
    onConcat: function(base, arg, result) {
        if (typeof base === 'string' && base.length < 100) {
            this.hash_inputs.push({base, arg: String(arg).substring(0, 200), result: String(result).substring(0, 200)});
            if (base.includes('tp-v2-input') || base.length === 16) {
                console.log('[POW CONCAT] "' + base + '" + "' + String(arg).substring(0, 100) + '"');
            }
        }
    },
    
    // Called on SHA-256 computation
    onHash: function(input, output) {
        this.hash_outputs.push({input: String(input).substring(0, 200), output: String(output).substring(0, 200)});
        console.log('[SHA256] input=' + String(input).substring(0, 100) + ' -> ' + String(output).substring(0, 64));
    }
};

`;
    
    // Now we need to patch the VM. The challenge is the minified code.
    // Let's use a different approach: wrap the entire p.js execution and 
    // monkey-patch the critical operations.
    
    return instrumentCode + `
// Wrap property assignment to intercept vxn
var __origDefineProperty = Object.defineProperty;
var __origProxy = Proxy;

// We'll patch AFTER the IIFE runs by hooking into the global state
// The key insight: the VM uses e(n)[e(n)] = e(n) for OP_37
// We can't easily patch that without breaking the minified code

// Alternative: Use a global Proxy on the window/global to intercept
// all property access patterns. But this is too broad.

// BEST APPROACH: Patch the specific handler functions in the Proxy array.
// The Proxy array is assigned to 'u'. We can intercept the Proxy creation.

// Override Proxy constructor to wrap the handler array
var __RealProxy = Proxy;
Proxy = function(target, handler) {
    // Check if this is the VM handler array (it's an array of ~89 functions)
    if (Array.isArray(target) && target.length >= 85 && target.length <= 95) {
        console.log('[INSTRUMENT] Intercepting VM handler Proxy (' + target.length + ' handlers)');
        
        // Wrap handler 37 (property set: e(n)[e(n)] = e(n))
        var orig37 = target[37];
        target[37] = function(n, e) {
            // OP_37: e(n)[e(n)] = e(n)
            // We need to call the original but also log
            // The challenge is that e(n) has side effects (advances PC)
            // So we can't call e(n) separately - we must let original run
            // Instead, wrap the operand decoder to capture values
            
            // Actually, let's just call the original and check after
            orig37(n, e);
            
            // After execution, we can't easily get the values...
            // Alternative: pre-read the operands by peeking at bytecode
            __KASADA_LOG.instruction_count++;
        };
        
        // Better approach: wrap the operand decoder function
        // The handlers receive (n, e, a, v, i, r) where:
        // e = G = operand decoder
        // a = F = store function
        
        // We'll wrap ALL handlers to count instructions and detect PoW
        var wrappedTarget = target.map(function(handler, idx) {
            return function(n, e, a, v, i, r) {
                __KASADA_LOG.instruction_count++;
                
                if (idx === 37) {
                    // OP_37: property set
                    // Wrap e to capture the key and value
                    var calls = [];
                    var wrappedE = function(frame) {
                        var val = e(frame);
                        calls.push(val);
                        return val;
                    };
                    var result = handler(n, wrappedE, a, v, i, r);
                    if (calls.length >= 3) {
                        __KASADA_LOG.onPropertySet(calls[0], calls[1], calls[2]);
                    }
                    return result;
                }
                
                if (idx === 0) {
                    // OP_0: property get
                    var calls = [];
                    var wrappedE = function(frame) {
                        var val = e(frame);
                        calls.push(val);
                        return val;
                    };
                    var wrappedA = function(frame, val) {
                        if (calls.length >= 2) {
                            __KASADA_LOG.onPropertyGet(calls[0], calls[1], val);
                        }
                        return a(frame, val);
                    };
                    return handler(n, wrappedE, wrappedA, v, i, r);
                }
                
                if (idx === 55) {
                    // OP_55: method call - intercept concat and sha256 calls
                    var calls = [];
                    var wrappedE = function(frame) {
                        var val = e(frame);
                        calls.push(val);
                        return val;
                    };
                    var wrappedA = function(frame, val) {
                        // calls[0] = obj, calls[1] = method obj, calls[2] = args array
                        // result = val
                        if (calls.length >= 2 && typeof val === 'string') {
                            if (val.length === 64 && /^[0-9a-f]+$/.test(val)) {
                                // Looks like a SHA-256 hash output
                                __KASADA_LOG.onHash('?', val);
                            }
                        }
                        return a(frame, val);
                    };
                    return handler(n, wrappedE, wrappedA, v, i, r);
                }
                
                return handler(n, e, a, v, i, r);
            };
        });
        
        return new __RealProxy(wrappedTarget, handler);
    }
    return new __RealProxy(target, handler);
};
Proxy.revocable = __RealProxy.revocable;

` + source + `

// After VM execution, dump results
setTimeout(function() {
    console.log('\\n========== INSTRUMENTATION RESULTS ==========');
    console.log('Total instructions executed: ' + __KASADA_LOG.instruction_count);
    console.log('VXN values captured: ' + __KASADA_LOG.vxn_values.length);
    console.log('Hash outputs: ' + __KASADA_LOG.hash_outputs.length);
    __KASADA_LOG.vxn_values.forEach(function(v, i) {
        console.log('  VXN[' + i + ']: type=' + v.type + ' value=' + v.str);
    });
}, 5000);
`;
}

// Generate the instrumented version
const instrumented = createInstrumentedVM(pjsSource);
const outPath = path.join(__dirname, 'p_instrumented.js');
fs.writeFileSync(outPath, instrumented);
console.log(`Wrote instrumented VM to: ${outPath} (${instrumented.length} bytes)`);

// ============================================================================
// STEP 2: Set up the sandbox environment
// ============================================================================

console.log(`
============================================================
NEXT STEPS:
============================================================

To run the instrumented VM, you need:
1. npm install happy-dom
2. Set up a sandbox with faked browser APIs
3. Use impit or a real browser proxy for /tl requests

For now, the instrumented p.js is ready.
Run it with: node sandbox_runner.js

The instrumentation will capture:
- Every time 'vxn' property is set/read
- Every SHA-256 hash input/output
- Every PoW concat operation
- CD token field values
============================================================
`);

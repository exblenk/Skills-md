---
name: "Frida Hook Debugging"
description: "Identify and fix crashing Frida hooks by isolating problematic instrumentation, testing safe alternatives, and avoiding recursive/self-referential hook patterns"
trigger: /frida-debug
source: auto
---

## Frida Hook Crash Debugging Checklist

When a Frida script loads hooks but then crashes or loops infinitely, follow this isolation pattern:

### 1. **Identify the Crashing Hook**
- Add logging before/after each hook section loads
- Remove suspect sections one at a time (newest first)
- Narrow down to the exact hook causing the issue

### 2. **Common Crash Patterns**

**Infinite Recursion / Deadlock:**
- Avoid `Interceptor.replace` on functions that Frida uses internally (e.g., `_dyld_*`, memory/file functions)
- Avoid calling hooked functions from within hook handlers (check caller module first)
- If hooking `exit()`/`abort()`/`fork()`, use `Interceptor.attach` with safe threading, not `replace`

**Memory Read Crashes:**
- Don't use `readByteArray()` or `readUtf8String()` on arbitrary/potentially invalid addresses
- Especially dangerous in "hot" functions (called frequently) like `memcmp`, memory allocation
- Use bounds checking or skip reads on untrusted addresses

**Control Flow Corruption:**
- Don't manipulate PC (program counter) directly — `context.pc += 4` skips instructions but destroys register state
- Exception handlers that retry faulting instructions via PC manipulation → infinite loop
- Let the OS handle exceptions; only intercept for logging

**Incorrect Function Signatures:**
- `Interceptor.replace` must match the actual native function signature exactly
- Wrong arg count or types → access violations when calling replaced function
- When in doubt, use `Interceptor.attach` (safer, only intercepts, doesn't replace)

### 3. **Safe Hook Patterns**

**For process termination functions:**
```javascript
// ✗ BAD: blocks Frida's own exit
Interceptor.replace(Module.getExportByName(null, 'exit'), 
  new NativeFunction(ptr(0), 'void', ['int']));

// ✓ GOOD: only blocks from app module, deferred startup
setTimeout(() => {
  Interceptor.attach(Module.getExportByName(null, 'exit'), {
    onEnter: (args) => {
      if (caller_in_app_module()) {
        Thread.sleep(86400); // block caller indefinitely
      }
    }
  });
}, 100);
```

**For system functions used internally:**
- Use `Interceptor.attach` only, never `replace`
- Check `this.context.pc` or `Thread.backtrace()` to verify caller is from target app, not system

**For memory reads:**
- Wrap in try/catch or check address validity first
- Avoid in frequently-called functions
- Use `ptr(addr).readCString()` only on guaranteed-valid strings

### 4. **Testing Safe Versions**

When narrowing down a crash:
1. Remove the newest/most complex hooks
2. Replace `Interceptor.replace` → `Interceptor.attach` 
3. Defer hook setup with `setTimeout(fn, 100)`
4. Remove memory reads from hot functions
5. Test and re-add hooks one at a time

### 5. **Exception Handlers (Use with Caution)**

- Do NOT return `true` to retry faulting instructions — infinite loop
- Do NOT modify `context.pc` to skip instructions — corrupts register state
- If you must handle exceptions: log only, then return `false` (let OS handle it)
- Better: avoid exception handlers entirely, fix the root cause instead

### 6. **Debugging Output**

Add before each hook section:
```javascript
console.log('[HOOK] SectionName -- loading');
// ... hook code ...
console.log('[HOOK] SectionName -- loaded');
```

This reveals exactly which hook crashes the app (last logged message = culprit).

## Summary
Frida crashes usually stem from **recursion** (hooking internal functions), **memory reads** (arbitrary addresses), or **state corruption** (PC manipulation). Test by isolating to the crashing hook, converting `replace` → `attach`, deferring setup, and avoiding memory operations in hot paths.

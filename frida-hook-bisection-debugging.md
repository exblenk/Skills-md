---
name: "Frida Hook Bisection Debugging"
description: "Isolate which Frida hooks are causing crashes by progressively enabling them in groups with diagnostic checkpoints"
trigger: /frida-bisect
source: auto
---

## Frida Hook Bisection for Crash Isolation

When a Frida instrumentation script causes the target process to crash and you need to identify which specific hook is responsible:

### Step 1: Create a Minimal Baseline
- Start with only essential anti-detection hooks (Frida self-protection, basic anti-debug)
- Add a heartbeat timer that logs "alive" every N seconds
- Verify the app stays alive with this minimal set
- If it crashes here, the problem is detection or core infrastructure, not specific hooks

### Step 2: Organize Remaining Hooks into Groups
Divide remaining hooks into logical categories by type/purpose:
- Example: File hooks, Dyld hooks, ObjC runtime, SSL/TLS, Screen capture, Security frameworks, Keychain, etc.
- 5-7 groups typically works well

### Step 3: Staggered Activation
- Enable each group at different time intervals (e.g., 2s, 5s, 8s, 11s, 14s)
- Keep the heartbeat logging so you can see exactly which interval the app dies
- The last group to load before silence is the culprit

### Step 4: Narrow Further (if needed)
- Once you identify the problematic group, extract individual hooks from it
- Repeat steps 2-3 on just that group
- Isolate the exact hook causing the issue

### Key Points
- Heartbeat logging is critical for precision—you need to know exactly when death occurs
- Start minimal and add incrementally; don't load everything at once
- Log hook loading with distinct markers so you can correlate output with timeline
- Use `setTimeout()` to control load timing in Frida

### Example Pattern
```javascript
let timeline = {};

function load_group_A() {
  console.log("[BISECT] 2s: Loading group A (file hooks)");
  // hook code here
  timeline.A = 2;
}

function heartbeat() {
  let elapsed = (Date.now() - start) / 1000;
  console.log(`[HEARTBEAT] t=${Math.floor(elapsed)}s`);
}

setTimeout(load_group_A, 2000);
setInterval(heartbeat, 1000);
```

This technique transforms a binary "does it crash?" problem into a linear search problem, often revealing the culprit in 4-5 test runs instead of 20+.


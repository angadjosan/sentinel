# Why the dual-build architecture

The core tension is this: **the sanitizer build is a better oracle, but the plain build is a more accurate simulation of production.** Neither alone is sufficient.

---

## What the plain build buys you

The plain build is what runs in production. It has:

- **Real memory layout.** ASAN inserts "red zones" — guard regions between allocations — and a shadow memory map. This changes the heap layout non-trivially. A heap overflow that corrupts a function pointer in production might land in a red zone under ASAN and crash immediately without completing the exploit. Conversely, some bugs that only trigger in specific heap configurations are masked by ASAN's shadow memory. The plain build is the ground truth for *whether the bug is actually exploitable as a memory corruption chain*.

- **Normal runtime performance.** ASAN adds ~2x overhead, MSAN ~3x, TSAN up to 10x. For timing-sensitive exploits (race conditions at the HTTP layer, auth replay windows), the sanitizer-induced slowdown can shift scheduling in ways that prevent reproduction.

- **Behavioral exploit confirmation.** SQL injection exfiltrating real data, auth bypass returning a 200 with the wrong user's payload, SSRF reaching an internal endpoint — these are *logic* proofs, not sanitizer events. The plain build is where you demonstrate "data left the system" or "I got in without credentials." The sanitizer is irrelevant here because logic bugs don't fire ASan errors.

---

## What the sanitizer build buys you

The sanitizer build is the forensic instrument.

- **Deterministic crash detection.** A heap overflow on a plain build may not crash at all — the corrupted bytes might overwrite padding, or the corruption might only be reached much later (use-after-free often crashes long after the free, in completely unrelated code). ASAN makes the crash happen *at the point of violation*, with a full stack trace and the exact corrupted allocation details. Without this, your evidence is "it eventually segfaulted" — weak and hard to reproduce.

- **Bug classes the plain build hides entirely.** MSAN catches reads of uninitialized memory. There's no clean signal for this on a plain build — the program reads garbage and either produces wrong output or crashes mysteriously later. MSAN fires immediately with the stack trace of both the uninitialized write and the bad read. Similarly, TSAN catches data races by instrumenting every memory access — on a plain build, a race condition may only manifest once in 10,000 runs depending on scheduler timing.

- **High-quality evidence for the confirmation oracle.** The confirmation oracle requires either a sanitizer error with a stack trace *or* a behavioral proof. The sanitizer stack trace is the gold standard for memory safety findings: it names the exact violation type (heap-buffer-overflow, use-after-free, etc.), the address, the size, the allocation site, and the free site. This is what goes into the `evidence` field on the finding and the `CONFIRMED_EXPLOIT` edge. You can't construct that from a plain segfault.

---

## Why you need both simultaneously

The agent attacks both builds simultaneously — not sequentially. Here's why concurrency matters:

1. **Different confirmation paths, same payload.** A given exploit payload might produce a behavioral proof on the plain build (data exfiltrated) *and* a sanitizer crash on the ASAN build. Running them in parallel means the same payloads hit both targets; you don't have to run the fuzzing campaign twice.

2. **Coverage the other build misses.** Some bugs crash the sanitizer build but not the plain build (ASAN exposes them). Some bugs crash the plain build but ASAN masks them (layout-sensitive). Attacking both simultaneously maximizes what you catch in a single campaign.

3. **The fuzzing tier specifically needs the sanitizer.** libFuzzer + ASAN is the standard memory fuzzing stack — coverage instrumentation works with the same clang pass that ASAN uses, and the sanitizer is what converts a "found interesting input" into "confirmed crash with stack trace." But the fuzzer still targets the same code paths the plain build runs. The plain build gives you the behavioral confirmation ("this input triggered authentication bypass") while the sanitizer build gives you the memory oracle ("this input triggered heap-buffer-overflow at line 247").

---

## When you only need the plain build

Interpreted language apps (pure Python/Ruby/Node with no C extensions) skip the sanitizer tier entirely. The sanitizer is specifically for:
- C/C++ code
- CGo
- Python C extensions
- Node native addons (N-API)
- JNI
- Rust FFI

For a pure Rails or pure Python app, all findings are behavioral (logic bugs, injection, auth gaps) — the plain build is sufficient. The sanitizer is the memory safety oracle, and memory safety is only a native-code concern.

---

## Summary

| | Plain build | Sanitizer build |
|---|---|---|
| **What it confirms** | Behavioral exploits (data exfil, auth bypass, command exec) | Memory safety violations (overflow, UAF, uninitialized read, race) |
| **Evidence quality** | Behavioral proof artifact | Sanitizer stack trace with exact violation type and location |
| **When it fails** | Misses bugs that don't crash cleanly (heap overflow into padding) | Masks bugs whose layout-sensitive behavior ASAN eliminates |
| **Performance** | Full speed — accurate to production | 2–10x slower; affects timing-sensitive attacks |
| **Required for** | Logic vulns on any language | Memory safety vulns on native code |

The dual-build architecture is necessary because **no single build can be both a faithful production replica and a memory safety oracle at the same time.** The sanitizer changes the environment enough that you'd miss real exploits if you only used it, and you'd miss memory safety confirmation if you only used the plain build.

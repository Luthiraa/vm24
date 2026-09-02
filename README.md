# vm16

vm16 is a **24 KiB static PIE WebAssembly sandbox** for small, untrusted agent workers on x86-64 Linux. The complete executable is exactly 24,576 bytes. It has no libc, dynamic loader, heap allocator, filesystem API, or network API.

Its intended use is one guest per process, communicating with a trusted supervisor over stdin/stdout. The supervisor owns tools, credentials, networking, storage, retries, and policy; the guest owns only bounded computation and linear memory.

## Build and run

Zig 0.16.0 is the only build dependency. Linux 3.17 or newer is required at runtime.

```sh
zig build
./zig-out/bin/vm16 agent.wasm [agent arguments...]
```

The default build runs all safety tests, creates the release ELF, verifies its load-segment invariants, strips non-runtime section metadata, and fails unless the final artifact is at most 24,576 bytes.

## Guest profile

vm16 deliberately implements a useful, auditable WebAssembly profile rather than pretending to be a general-purpose runtime:

- `i32` and `i64`, including the MVP integer instruction set and sign-extension operations
- structured control flow, direct calls, tables, and checked `call_indirect`
- bounded memory, globals, active element segments, active/passive data segments
- bulk `memory.init`, `data.drop`, `memory.copy`, and `memory.fill`
- up to 255 types, 2,048 functions, 32 parameters, 128 globals/exports/data segments, and a 1,024-entry table
- `_start`, `main`, and the standard start section
- WASI Preview 1 and `wasi_unstable`: process exit, stdin/stdout/stderr, arguments, empty environment, random bytes, clocks, descriptor metadata/close, and yield
- capability-shaped WASI imports may link; unavailable calls return `ENOTCAPABLE` when their signature permits, without granting ambient authority

Float, SIMD, threads, reference types, exceptions, multi-memory, imported memory/table/globals, direct filesystem access, and direct network access are rejected. Compile guests for an integer-only `wasm32-wasi` profile and use newline-delimited JSON or another framed stdin/stdout protocol for agent tool calls.

## Layered containment

Every function is parsed and stack-type-validated before execution. Runtime checks independently cover value/control stacks, locals, globals, call depth, indirect-call signatures, integer traps, tables, memory ranges, bulk operations, and host buffers.

| Limit | Default |
|---|---:|
| WebAssembly fuel | 50,000,000 units |
| Linear memory | 64 MiB demand-paged |
| Module | 4 MiB |
| Nested calls | 64 |
| Value stack / control labels | 4,096 / 128 |
| stdin / stdout+stderr | 1 MiB each |
| CPU / wall time | 5 s / 10 s |
| Process address space / stack | 96 MiB / 1 MiB |
| Open descriptors | stdin, stdout, stderr only |

The launcher copies the module into immutable anonymous memory, maps code RX and state RW (never RWX), closes inherited descriptors above stderr, disables core dumps and process dumpability, enables `PR_SET_NO_NEW_PRIVS`, and installs a seccomp allowlist. Guest execution can invoke only `read`, `write`, `clock_gettime`, `getrandom`, and process exit syscalls. Setup or containment failure terminates the process before guest code runs.

## Verification

```sh
zig build                 # tests + release + ELF checks + size gate
zig build test            # tests in src/vm_test.zig
zig build test --fuzz     # coverage-guided parser/validator fuzzing
```

The release ELF is sectionless by design: Linux loads program headers, not debugging sections. The build-side trimmer refuses non-PIE, non-x86-64, sub-page-aligned, W+X, malformed, or oversized output before installation.

## Exit codes

| Code | Meaning |
|---:|---|
| guest code | clean return or `proc_exit` |
| 1 | malformed module or runtime trap |
| 2 | launcher, input, process-limit, or seccomp failure |
| 3 | unsupported WebAssembly or host feature |
| 124 | VM resource limit exhausted |

## Status

vm16 is production-hardened for its narrow stdin/stdout worker model, but it has not yet had an independent security audit or completed differential testing against the full upstream WebAssembly specification suite. Treat those as release requirements before exposing it to hostile multi-tenant workloads. Smallness improves auditability; it is not evidence of correctness by itself.

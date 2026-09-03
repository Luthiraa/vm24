# vm16

`vm16` is a tiny, single-process WebAssembly runtime for untrusted stdin/stdout workers on x86-64 Linux.

It is a real interpreter and sandbox written in freestanding Zig. There is no mock execution path, libc, heap allocator, filesystem access, network access, or JIT. `src/vm.zig` parses, validates, instantiates, and interprets the guest; `src/main.zig` provides the Linux process boundary and WASI host calls.

## Build and run

Requirements: Zig 0.16.0 and x86-64 Linux.

```sh
zig build
./zig-out/bin/vm16 worker.wasm [args...]
```

The build runs tests, creates the release binary, trims unnecessary ELF metadata, and enforces the 24 KiB final-size limit.

```sh
zig build test
```

Tests cover malformed modules, parser fuzzing, integer traps, fuel exhaustion, bounded memory, WASI behavior, and invalid linear-memory access.

## Supported guest profile

- WebAssembly i32 and i64 instructions
- sign-extension and bulk-memory instructions
- one table and one linear memory
- narrow WASI `snapshot_preview1` / `wasi_unstable`
- stdin/stdout/stderr, arguments, random bytes, clocks, close, and exit
- integer-only `wasm32-wasi` guests

Floating point, SIMD, threads, exception handling, and direct system calls are not supported. Unknown WASI imports fail closed.

## Fixed limits

| Resource | Default |
|---|---:|
| Guest fuel | 50 million instructions |
| Guest linear memory | 64 MiB |
| Operand stack | 4,096 values |
| Call depth | 64 frames |
| Guest input/output | 1 MiB each |
| Module size | 4 MiB |
| Process CPU / wall time | 5s / 10s |
| Native address space | 96 MiB |

These values are deliberately hardcoded as the launcher's fixed policy. The VM exposes `Limits` for tests and embedding, while the CLI uses the defaults.

## Containment

Before running the guest, the launcher makes the module read-only, reserves guest memory, closes inherited file descriptors, applies resource limits, disables core dumps, enables `PR_SET_NO_NEW_PRIVS`, and installs seccomp.

After lockdown, only the syscalls needed by the host interface are allowed: `read`, `write`, `exit`, `exit_group`, `getrandom`, and `clock_gettime`.

## Exit codes

| Code | Meaning |
|---:|---|
| guest code | Normal guest/WASI exit |
| 1 | Trap or malformed module |
| 2 | Launcher/setup failure |
| 3 | Unsupported feature |
| 124 | Limit reached |

## Scope

This is a small, auditable experiment and constrained worker runtime—not a full Wasm engine or independently security-audited sandbox. For hostile multi-tenant production use, add an outer isolation layer such as a separate user, container, or VM boundary.

## Layout

```text
src/main.zig       Linux launcher, raw syscalls, limits, seccomp
src/vm.zig         Wasm parser, validator, interpreter, WASI bridge
src/vm_test.zig    Unit tests and fuzz target
tools/trim_elf.zig ELF validation and size trimming
link.ld            Minimal linker script
build.zig          Build, test, trim, and size-check pipeline
```

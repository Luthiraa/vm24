<img width="100" alt="ChatGPT_Image_Sep_3__2026__03_06_36_PM__1_-removebg-preview" src="https://github.com/user-attachments/assets/2ba38f94-b257-43f5-a3ba-bcfb48b8527e" />


# vm24

`vm24` is a tiny WebAssembly runtime for running untrusted stdin/stdout workers on x86-64 Linux.

It is a real interpreter and sandbox written in freestanding Zig. No libc, heap, filesystem, network, or JIT. The VM parses, validates, instantiates, and runs the guest itself.

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

Tests cover malformed modules, parser fuzzing, traps, fuel exhaustion, bounded memory, WASI behavior, and invalid memory access.

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

These are deliberately hardcoded limits for the launcher. The VM exposes `Limits` for tests and embedding.

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

This is a small, auditable experiment and constrained worker runtime—not a full Wasm engine or independently audited sandbox. For hostile multi-tenant workloads, use an outer isolation layer too.

## Layout

```text
src/main.zig       Linux launcher, raw syscalls, limits, seccomp
src/vm.zig         Wasm parser, validator, interpreter, WASI bridge
src/vm_test.zig    Unit tests and fuzz target
tools/trim_elf.zig ELF validation and size trimming
link.ld            Minimal linker script
build.zig          Build, test, trim, and size-check pipeline
```

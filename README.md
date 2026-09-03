# vm24

24 KiB static PIE WebAssembly sandbox for untrusted stdin/stdout workers on x86-64 Linux. No libc, heap, filesystem, or network — one guest per process, supervisor owns everything else.

```sh
zig build
./zig-out/bin/vm16 agent.wasm [args...]
```

Zig 0.16.0 to build. Linux 3.17+ to run. `zig build` runs tests, trims the ELF, and enforces the 24 KiB size limit.

**Wasm profile:** i32/i64 MVP + sign-ext, bulk memory, tables, narrow WASI (stdio, args, random, clocks, exit). Compile guests as integer-only `wasm32-wasi`. No float, SIMD, threads, or direct I/O.

**Containment:** parse and validate before execution, fuel/memory/stack limits, seccomp allowlist (`read`/`write`/`exit`/`getrandom`/`clock_gettime` only), closed inherited fds, no core dumps. Defaults: 50M fuel, 64 MiB linear memory, 1 MiB stdio, 5s CPU / 10s wall.

| exit | meaning |
|---:|---|
| guest code | clean return |
| 1 | trap or bad module |
| 2 | launcher/setup failure |
| 3 | unsupported feature |
| 124 | limit hit |

`zig build test` — unit tests. `zig build test --fuzz` — parser/validator fuzzing.

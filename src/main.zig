const vm = @import("vm.zig");

const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_CLOSE: usize = 3;
const SYS_FSTAT: usize = 5;
const SYS_MMAP: usize = 9;
const SYS_MPROTECT: usize = 10;
const SYS_ALARM: usize = 37;
const SYS_EXIT: usize = 60;
const SYS_GETRLIMIT: usize = 97;
const SYS_PRCTL: usize = 157;
const SYS_SETRLIMIT: usize = 160;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_EXIT_GROUP: usize = 231;
const SYS_OPENAT: usize = 257;
const SYS_SECCOMP: usize = 317;
const SYS_GETRANDOM: usize = 318;
const SYS_CLOSE_RANGE: usize = 436;

const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const MAP_PRIVATE: usize = 0x02;
const MAP_ANON: usize = 0x20;
const AT_FDCWD: isize = -100;
const O_RDONLY_CLOEXEC_NONBLOCK: usize = 0x80800;
const PR_SET_DUMPABLE: usize = 4;
const PR_SET_NO_NEW_PRIVS: usize = 38;
const SECCOMP_SET_MODE_FILTER: usize = 1;
const GUEST_MEMORY: usize = 1024 * 65536;
const MAX_MODULE: usize = 4 * 1024 * 1024;

fn sys3(n: usize, a: usize, b: usize, c: usize) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [n] "{rax}" (n),
          [a] "{rdi}" (a),
          [b] "{rsi}" (b),
          [c] "{rdx}" (c),
        : .{ .rcx = true, .r11 = true });
}

fn sys6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) isize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> isize),
        : [n] "{rax}" (n),
          [a] "{rdi}" (a),
          [b] "{rsi}" (b),
          [c] "{rdx}" (c),
          [d] "{r10}" (d),
          [e] "{r8}" (e),
          [f] "{r9}" (f),
        : .{ .rcx = true, .r11 = true });
}

fn die(code: u8) noreturn {
    _ = sys3(SYS_EXIT, code, 0, 0);
    unreachable;
}

fn fail(message: []const u8) noreturn {
    _ = sys3(SYS_WRITE, 2, @intFromPtr(message.ptr), message.len);
    die(2);
}

fn mmap(len: usize, prot: usize, flags: usize, fd: isize) ?[*]u8 {
    const r = sys6(SYS_MMAP, 0, len, prot, flags, @bitCast(fd), 0);
    return if (r < 0) null else @ptrFromInt(@as(usize, @intCast(r)));
}

const LinuxHost = struct {
    argv: [*]const [*]const u8,
    argc: usize,
    input_used: u64 = 0,
    output_used: u64 = 0,
    closed: u8 = 0,

    pub fn write(_: *@This(), fd: u32, bytes: []const u8) bool {
        var done: usize = 0;
        while (done < bytes.len) {
            const n = sys3(SYS_WRITE, fd, @intFromPtr(bytes.ptr + done), bytes.len - done);
            if (n <= 0) return false;
            done += @intCast(n);
        }
        return true;
    }
    pub fn read(_: *@This(), bytes: []u8) isize {
        if (bytes.len == 0) return 0;
        return sys3(SYS_READ, 0, @intFromPtr(bytes.ptr), bytes.len);
    }
    pub fn random(_: *@This(), bytes: []u8) bool {
        var done: usize = 0;
        while (done < bytes.len) {
            const n = sys3(SYS_GETRANDOM, @intFromPtr(bytes.ptr + done), bytes.len - done, 0);
            if (n <= 0) return false;
            done += @intCast(n);
        }
        return true;
    }
    pub fn clock(_: *@This(), id: u32) ?u64 {
        if (id > 3) return null;
        var ts: [2]i64 = .{ 0, 0 };
        if (sys3(SYS_CLOCK_GETTIME, id, @intFromPtr(&ts), 0) < 0) return null;
        return @as(u64, @intCast(ts[0])) * 1_000_000_000 + @as(u64, @intCast(ts[1]));
    }
    pub fn argCount(h: *@This()) usize {
        return h.argc;
    }
    pub fn arg(h: *@This(), i: usize) ?[]const u8 {
        if (i >= h.argc) return null;
        const p = h.argv[i];
        var n: usize = 0;
        while (n < 4096 and p[n] != 0) : (n += 1) {}
        return if (n == 4096) null else p[0..n];
    }
};

const Filter = extern struct { code: u16, jt: u8, jf: u8, k: u32 };
const FilterProgram = extern struct { len: u16, filter: [*]const Filter };

fn lockDown() bool {
    const LD: u16 = 0x20;
    const JEQ: u16 = 0x15;
    const RET: u16 = 0x06;
    const KILL: u32 = 0x80000000;
    const ALLOW: u32 = 0x7fff0000;
    var f = [_]Filter{
        .{ .code = LD, .jt = 0, .jf = 0, .k = 4 },
        .{ .code = JEQ, .jt = 1, .jf = 0, .k = 0xc000003e },
        .{ .code = RET, .jt = 0, .jf = 0, .k = KILL },
        .{ .code = LD, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = JEQ, .jt = 6, .jf = 0, .k = @intCast(SYS_READ) },
        .{ .code = JEQ, .jt = 5, .jf = 0, .k = @intCast(SYS_WRITE) },
        .{ .code = JEQ, .jt = 4, .jf = 0, .k = @intCast(SYS_EXIT) },
        .{ .code = JEQ, .jt = 3, .jf = 0, .k = @intCast(SYS_EXIT_GROUP) },
        .{ .code = JEQ, .jt = 2, .jf = 0, .k = @intCast(SYS_CLOCK_GETTIME) },
        .{ .code = JEQ, .jt = 1, .jf = 0, .k = @intCast(SYS_GETRANDOM) },
        .{ .code = RET, .jt = 0, .jf = 0, .k = KILL },
        .{ .code = RET, .jt = 0, .jf = 0, .k = ALLOW },
    };
    var prog = FilterProgram{ .len = f.len, .filter = &f };
    asm volatile (""
        :
        : [filter] "r" (&f),
          [program] "r" (&prog),
        : .{ .memory = true });
    if (sys3(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0) < 0) return false;
    return sys3(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, 0, @intFromPtr(&prog)) == 0;
}

fn closeExtraFds() bool {
    if (sys3(SYS_CLOSE_RANGE, 3, ~@as(usize, 0), 0) == 0) return true;
    var nofile: [2]usize = .{ 0, 0 };
    if (sys3(SYS_GETRLIMIT, 7, @intFromPtr(&nofile), 0) < 0 or nofile[0] > 1_048_576) return false;
    var fd: usize = 3;
    while (fd < nofile[0]) : (fd += 1) _ = sys3(SYS_CLOSE, fd, 0, 0);
    return true;
}

fn constrainProcess() bool {
    const limits = [_][2]usize{
        .{ 0, 5 }, // CPU seconds
        .{ 1, 1_048_576 }, // output bytes
        .{ 3, 1_048_576 }, // stack
        .{ 4, 0 }, // no core dumps
        .{ 7, 3 }, // stdin/stdout/stderr
        .{ 9, 96 * 1_048_576 }, // address space
    };
    for (limits, 0..) |value, resource| {
        var rlimit = value;
        if (sys3(SYS_SETRLIMIT, resource, @intFromPtr(&rlimit), 0) < 0) return false;
    }
    _ = sys3(SYS_ALARM, 10, 0, 0);
    return sys3(SYS_PRCTL, PR_SET_DUMPABLE, 0, 0) == 0;
}

export fn _start() callconv(.naked) noreturn {
    @setRuntimeSafety(false);
    asm volatile (
        \\xor %%ebp, %%ebp
        \\mov %%rsp, %%rdi
        \\and $-16, %%rsp
        \\call vm16_start
        ::: .{ .memory = true });
    unreachable;
}

export fn vm16_start(base: [*]const usize) callconv(.c) noreturn {
    const argc = base[0];
    if (argc < 2) fail("vm16: expected a wasm path\n");
    _ = sys3(SYS_ALARM, 10, 0, 0);
    const argv: [*]const [*]const u8 = @ptrCast(base + 1);
    const fd = sys6(SYS_OPENAT, @bitCast(AT_FDCWD), @intFromPtr(argv[1]), O_RDONLY_CLOEXEC_NONBLOCK, 0, 0, 0);
    if (fd < 0) fail("vm16: cannot open module\n");
    var stat: [144]u8 = .{0} ** 144;
    if (sys3(SYS_FSTAT, @intCast(fd), @intFromPtr(&stat), 0) < 0) fail("vm16: cannot stat module\n");
    const mode: u32 = @bitCast(stat[24..28].*);
    if (mode & 0o170000 != 0o100000) fail("vm16: module is not a regular file\n");
    const size: usize = @intCast(@as(u64, @bitCast(stat[48..56].*)));
    if (size < 8 or size > MAX_MODULE) fail("vm16: invalid module size\n");
    const file = mmap(size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1) orelse fail("vm16: cannot map module\n");
    var loaded: usize = 0;
    while (loaded < size) {
        const n = sys3(SYS_READ, @intCast(fd), @intFromPtr(file + loaded), size - loaded);
        if (n <= 0) fail("vm16: cannot read module\n");
        loaded += @intCast(n);
    }
    _ = sys3(SYS_CLOSE, @intCast(fd), 0, 0);
    if (sys3(SYS_MPROTECT, @intFromPtr(file), size, PROT_READ) < 0) fail("vm16: cannot protect module\n");
    const backing = mmap(GUEST_MEMORY, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1) orelse fail("vm16: cannot reserve memory\n");
    if (!closeExtraFds()) fail("vm16: cannot close inherited fds\n");
    if (!constrainProcess()) fail("vm16: cannot set process limits\n");
    if (!lockDown()) fail("vm16: cannot install seccomp\n");
    var host = LinuxHost{ .argv = argv + 1, .argc = argc - 1 };
    const outcome = vm.run(file[0..size], .{}, &host, backing[0..GUEST_MEMORY]);
    die(switch (outcome.trap) {
        .ok, .exit => outcome.code,
        .unsupported => 3,
        .limit => 124,
        else => 1,
    });
}

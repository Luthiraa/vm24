const vm = @import("vm.zig");

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
    _ = sys3(60, code, 0, 0);
    unreachable;
}

fn fail(message: []const u8) noreturn {
    _ = sys3(1, 2, @intFromPtr(message.ptr), message.len);
    die(2);
}

fn mmap(len: usize, prot: usize, flags: usize, fd: isize) ?[*]u8 {
    const r = sys6(9, 0, len, prot, flags, @bitCast(fd), 0);
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
            const n = sys3(1, fd, @intFromPtr(bytes.ptr + done), bytes.len - done);
            if (n <= 0) return false;
            done += @intCast(n);
        }
        return true;
    }
    pub fn read(_: *@This(), bytes: []u8) isize {
        if (bytes.len == 0) return 0;
        return sys3(0, 0, @intFromPtr(bytes.ptr), bytes.len);
    }
    pub fn random(_: *@This(), bytes: []u8) bool {
        var done: usize = 0;
        while (done < bytes.len) {
            const n = sys3(318, @intFromPtr(bytes.ptr + done), bytes.len - done, 0);
            if (n <= 0) return false;
            done += @intCast(n);
        }
        return true;
    }
    pub fn clock(_: *@This(), id: u32) ?u64 {
        if (id > 3) return null;
        var ts: [2]i64 = .{ 0, 0 };
        if (sys3(228, id, @intFromPtr(&ts), 0) < 0) return null;
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
    var f = [_]Filter{
        .{ .code = 0x20, .jt = 0, .jf = 0, .k = 4 },
        .{ .code = 0x15, .jt = 1, .jf = 0, .k = 0xc000003e },
        .{ .code = 0x06, .jt = 0, .jf = 0, .k = 0x80000000 },
        .{ .code = 0x20, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = 0x15, .jt = 6, .jf = 0, .k = 0 },
        .{ .code = 0x15, .jt = 5, .jf = 0, .k = 1 },
        .{ .code = 0x15, .jt = 4, .jf = 0, .k = 60 },
        .{ .code = 0x15, .jt = 3, .jf = 0, .k = 231 },
        .{ .code = 0x15, .jt = 2, .jf = 0, .k = 228 },
        .{ .code = 0x15, .jt = 1, .jf = 0, .k = 318 },
        .{ .code = 0x06, .jt = 0, .jf = 0, .k = 0x80000000 },
        .{ .code = 0x06, .jt = 0, .jf = 0, .k = 0x7fff0000 },
    };
    var prog = FilterProgram{ .len = f.len, .filter = &f };
    asm volatile (""
        :
        : [filter] "r" (&f),
          [program] "r" (&prog),
        : .{ .memory = true });
    if (sys3(157, 38, 1, 0) < 0) return false;
    return sys3(317, 1, 0, @intFromPtr(&prog)) == 0;
}

fn closeExtraFds() bool {
    if (sys3(436, 3, ~@as(usize, 0), 0) == 0) return true;
    var nofile: [2]usize = .{ 0, 0 };
    if (sys3(97, 7, @intFromPtr(&nofile), 0) < 0 or nofile[0] > 1_048_576) return false;
    var fd: usize = 3;
    while (fd < nofile[0]) : (fd += 1) _ = sys3(3, fd, 0, 0);
    return true;
}

fn constrainProcess() bool {
    const limits = [_][2]usize{
        .{ 0, 5 }, // CPU seconds
        .{ 1, 1_048_576 }, // output file bytes
        .{ 3, 1_048_576 }, // stack bytes
        .{ 4, 0 }, // core bytes
        .{ 7, 3 }, // open descriptors
        .{ 9, 96 * 1_048_576 }, // address space bytes
    };
    for (limits, 0..) |value, resource| {
        var rlimit = value;
        if (sys3(160, resource, @intFromPtr(&rlimit), 0) < 0) return false;
    }
    _ = sys3(37, 10, 0, 0); // wall-clock seconds
    return sys3(157, 4, 0, 0) == 0; // non-dumpable
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
    _ = sys3(37, 10, 0, 0);
    const argv: [*]const [*]const u8 = @ptrCast(base + 1);
    const fd = sys6(257, @bitCast(@as(isize, -100)), @intFromPtr(argv[1]), 0x80800, 0, 0, 0);
    if (fd < 0) fail("vm16: cannot open module\n");
    var stat: [144]u8 = .{0} ** 144;
    if (sys3(5, @intCast(fd), @intFromPtr(&stat), 0) < 0) fail("vm16: cannot stat module\n");
    const mode: u32 = @bitCast(stat[24..28].*);
    if (mode & 0o170000 != 0o100000) fail("vm16: module is not a regular file\n");
    const size: usize = @intCast(@as(u64, @bitCast(stat[48..56].*)));
    if (size < 8 or size > 4 * 1024 * 1024) fail("vm16: invalid module size\n");
    const file = mmap(size, 3, 0x22, -1) orelse fail("vm16: cannot map module\n");
    var loaded: usize = 0;
    while (loaded < size) {
        const n = sys3(0, @intCast(fd), @intFromPtr(file + loaded), size - loaded);
        if (n <= 0) fail("vm16: cannot read module\n");
        loaded += @intCast(n);
    }
    _ = sys3(3, @intCast(fd), 0, 0);
    if (sys3(10, @intFromPtr(file), size, 1) < 0) fail("vm16: cannot protect module\n");
    const memory_size = 1024 * 65536;
    const backing = mmap(memory_size, 3, 0x22, -1) orelse fail("vm16: cannot reserve memory\n");
    if (!closeExtraFds()) fail("vm16: cannot close inherited fds\n");
    if (!constrainProcess()) fail("vm16: cannot set process limits\n");
    if (!lockDown()) fail("vm16: cannot install seccomp\n");
    var host = LinuxHost{ .argv = argv + 1, .argc = argc - 1 };
    const outcome = vm.run(file[0..size], .{}, &host, backing[0..memory_size]);
    die(switch (outcome.trap) {
        .ok, .exit => outcome.code,
        .unsupported => 3,
        .limit => 124,
        else => 1,
    });
}

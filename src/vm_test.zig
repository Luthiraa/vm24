const std = @import("std");
const vm = @import("vm.zig");

const Host = struct {
    input_used: u64 = 0,
    output_used: u64 = 0,
    closed: u8 = 0,

    pub fn write(_: *@This(), _: u32, _: []const u8) bool {
        return true;
    }
    pub fn read(_: *@This(), _: []u8) isize {
        return 0;
    }
    pub fn random(_: *@This(), bytes: []u8) bool {
        @memset(bytes, 7);
        return true;
    }
    pub fn clock(_: *@This(), _: u32) ?u64 {
        return 1;
    }
    pub fn argCount(_: *@This()) usize {
        return 0;
    }
    pub fn arg(_: *@This(), _: usize) ?[]const u8 {
        return null;
    }
};

fn execute(bytes: []const u8, limits: vm.Limits, backing: []u8) vm.Outcome {
    var host = Host{};
    return vm.run(bytes, limits, &host, backing);
}

fn fuzzOne(_: void, smith: *std.testing.Smith) !void {
    var bytes: [4096]u8 = undefined;
    const len = smith.slice(&bytes);
    var memory: [1]u8 = undefined;
    _ = execute(bytes[0..len], .{ .fuel = 4096 }, &memory);
}

test "coverage-guided parser and validator fuzz target" {
    try std.testing.fuzz({}, fuzzOne, .{});
}

test "unknown WASI capabilities link but fail closed" {
    const wasm = [_]u8{
        0,   97,  115,  109,  1,    0,   0,    0,
        1,   5,   1,    0x60, 0,    1,   0x7f, 2,
        36,  1,   22,   'w',  'a',  's', 'i',  '_',
        's', 'n', 'a',  'p',  's',  'h', 'o',  't',
        '_', 'p', 'r',  'e',  'v',  'i', 'e',  'w',
        '1', 9,   'p',  'a',  't',  'h', '_',  'o',
        'p', 'e', 'n',  0,    0,    3,   2,    1,
        0,   7,   10,   1,    6,    '_', 's',  't',
        'a', 'r', 't',  0,    1,    10,  6,    1,
        4,   0,   0x10, 0,    0x0b,
    };
    var memory: [1]u8 = undefined;
    const got = execute(&wasm, .{}, &memory);
    try std.testing.expectEqual(vm.Trap.ok, got.trap);
    try std.testing.expectEqual(@as(u8, 76), got.code);
}

test "LEB decoding rejects overflow" {
    const wasm = [_]u8{ 0, 97, 115, 109, 1, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0x10 };
    var memory: [1]u8 = undefined;
    try std.testing.expectEqual(vm.Trap.malformed, execute(&wasm, .{}, &memory).trap);
}

test "linear addresses cannot wrap" {
    const wasm = [_]u8{
        0,    97,   115,  109,  1,   0,    0,    0,
        1,    5,    1,    0x60, 0,   1,    0x7f, 3,
        2,    1,    0,    5,    3,   1,    0,    1,
        7,    10,   1,    6,    '_', 's',  't',  'a',
        'r',  't',  0,    0,    10,  13,   1,    11,
        0,    0x41, 0x7f, 0x28, 2,   0xff, 0xff, 0xff,
        0xff, 0x0f, 0x0b,
    };
    var memory: [65536]u8 = undefined;
    try std.testing.expectEqual(vm.Trap.runtime, execute(&wasm, .{ .memory_pages = 1 }, &memory).trap);
}

test "fd_close revokes guest access" {
    const wasi = [_]u8{ 22, 'w', 'a', 's', 'i', '_', 's', 'n', 'a', 'p', 's', 'h', 'o', 't', '_', 'p', 'r', 'e', 'v', 'i', 'e', 'w', '1' };
    const wasm = [_]u8{
        0,    97, 115,  109,  1,    0,    0, 0,
        1,    18, 3,    0x60, 1,    0x7f, 1, 0x7f,
        0x60, 4,  0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f,
        0x60, 0,  1,    0x7f, 2,    69,   2,
    } ++ wasi ++ [_]u8{ 8, 'f', 'd', '_', 'c', 'l', 'o', 's', 'e', 0, 0 } ++ wasi ++ [_]u8{
        8,   'f',  'd',  '_',  'w',  'r',  'i',  't',  'e', 0,
        1,   3,    2,    1,    2,    7,    10,   1,    6,   '_',
        's', 't',  'a',  'r',  't',  0,    2,    10,   19,  1,
        17,  0,    0x41, 1,    0x10, 0,    0x1a, 0x41, 1,   0x41,
        0,   0x41, 0,    0x41, 0,    0x10, 1,    0x0b,
    };
    var memory: [1]u8 = undefined;
    const got = execute(&wasm, .{}, &memory);
    try std.testing.expectEqual(vm.Trap.ok, got.trap);
    try std.testing.expectEqual(@as(u8, 8), got.code);
}

test "validator rejects a result type mismatch" {
    const wasm = [_]u8{
        0,   97,  115, 109,  1,    0, 0,    0,
        1,   5,   1,   0x60, 0,    1, 0x7f, 3,
        2,   1,   0,   7,    10,   1, 6,    '_',
        's', 't', 'a', 'r',  't',  0, 0,    10,
        6,   1,   4,   0,    0x42, 0, 0x0b,
    };
    var memory: [1]u8 = undefined;
    try std.testing.expectEqual(vm.Trap.malformed, execute(&wasm, .{}, &memory).trap);
}

test "integer division by zero traps" {
    const wasm = [_]u8{
        0,    97,   115, 109,  1,    0, 0,    0,
        1,    5,    1,   0x60, 0,    1, 0x7f, 3,
        2,    1,    0,   7,    10,   1, 6,    '_',
        's',  't',  'a', 'r',  't',  0, 0,    10,
        9,    1,    7,   0,    0x41, 1, 0x41, 0,
        0x6e, 0x0b,
    };
    var memory: [1]u8 = undefined;
    try std.testing.expectEqual(vm.Trap.runtime, execute(&wasm, .{}, &memory).trap);
}

test "runs a validated integer module" {
    const wasm = [_]u8{
        0,   97,  115, 109,  1,    0,  0,    0,
        1,   5,   1,   0x60, 0,    1,  0x7f, 3,
        2,   1,   0,   7,    10,   1,  6,    '_',
        's', 't', 'a', 'r',  't',  0,  0,    10,
        6,   1,   4,   0,    0x41, 42, 0x0b,
    };
    var memory: [1]u8 = undefined;
    const got = execute(&wasm, .{}, &memory);
    try std.testing.expectEqual(vm.Trap.ok, got.trap);
    try std.testing.expectEqual(@as(u8, 42), got.code);
}

test "fuel stops an infinite loop" {
    const wasm = [_]u8{
        0,    97,  115, 109,  1,    0,    0,   0,
        1,    4,   1,   0x60, 0,    0,    3,   2,
        1,    0,   7,   10,   1,    6,    '_', 's',
        't',  'a', 'r', 't',  0,    0,    10,  9,
        1,    7,   0,   0x03, 0x40, 0x0c, 0,   0x0b,
        0x0b,
    };
    var memory: [1]u8 = undefined;
    try std.testing.expectEqual(vm.Trap.limit, execute(&wasm, .{ .fuel = 20 }, &memory).trap);
}

test "calls preserve parameter order" {
    const wasm = [_]u8{
        0,    97,   115, 109,  1,    0,    0,    0,
        1,    11,   2,   0x60, 2,    0x7f, 0x7f, 1,
        0x7f, 0x60, 0,   1,    0x7f, 3,    3,    2,
        0,    1,    7,   10,   1,    6,    '_',  's',
        't',  'a',  'r', 't',  0,    1,    10,   18,
        2,    7,    0,   0x20, 0,    0x20, 1,    0x6b,
        0x0b, 8,    0,   0x41, 7,    0x41, 2,    0x10,
        0,    0x0b,
    };
    var memory: [1]u8 = undefined;
    const got = execute(&wasm, .{}, &memory);
    try std.testing.expectEqual(vm.Trap.ok, got.trap);
    try std.testing.expectEqual(@as(u8, 5), got.code);
}

test "linear memory stays bounded" {
    const wasm = [_]u8{
        0,    97,   115,  109,  1,   0,    0,    0,
        1,    5,    1,    0x60, 0,   1,    0x7f, 3,
        2,    1,    0,    5,    3,   1,    0,    1,
        7,    10,   1,    6,    '_', 's',  't',  'a',
        'r',  't',  0,    0,    10,  16,   1,    14,
        0,    0x41, 0,    0x41, 42,  0x36, 2,    0,
        0x41, 0,    0x28, 2,    0,   0x0b,
    };
    var memory: [65536]u8 = undefined;
    const got = execute(&wasm, .{ .memory_pages = 1 }, &memory);
    try std.testing.expectEqual(vm.Trap.ok, got.trap);
    try std.testing.expectEqual(@as(u8, 42), got.code);
}

test "bulk memory and passive data are validated" {
    const wasm = [_]u8{
        0,    97,   115,  109,  1,    0,    0,    0,
        1,    5,    1,    0x60, 0,    1,    0x7f, 3,
        2,    1,    0,    5,    3,    1,    0,    1,
        7,    10,   1,    6,    '_',  's',  't',  'a',
        'r',  't',  0,    0,    12,   1,    1,    10,
        41,   1,    39,   0,    0x41, 0,    0x41, 7,
        0x41, 4,    0xfc, 11,   0,    0x41, 1,    0x41,
        0,    0x41, 3,    0xfc, 8,    0,    0,    0xfc,
        9,    0,    0x41, 0,    0x41, 0,    0x41, 0,
        0xfc, 8,    0,    0,    0x41, 2,    0x2d, 0,
        0,    0x0b, 11,   6,    1,    1,    3,    'A',
        'B',  'C',
    };
    var memory: [65536]u8 = undefined;
    const got = execute(&wasm, .{ .memory_pages = 1 }, &memory);
    try std.testing.expectEqual(vm.Trap.ok, got.trap);
    try std.testing.expectEqual(@as(u8, 'B'), got.code);
}

test "sign extension matches WebAssembly" {
    const wasm = [_]u8{
        0,    97,  115, 109,  1,    0,    0,    0,
        1,    5,   1,   0x60, 0,    1,    0x7f, 3,
        2,    1,   0,   7,    10,   1,    6,    '_',
        's',  't', 'a', 'r',  't',  0,    0,    10,
        8,    1,   6,   0,    0x41, 0xff, 1,    0xc0,
        0x0b,
    };
    var memory: [1]u8 = undefined;
    const got = execute(&wasm, .{}, &memory);
    try std.testing.expectEqual(vm.Trap.ok, got.trap);
    try std.testing.expectEqual(@as(u8, 255), got.code);
}

test "corrupt modules never escape the parser" {
    const good = [_]u8{
        0,   97,  115, 109,  1, 0, 0,   0,
        1,   4,   1,   0x60, 0, 0, 3,   2,
        1,   0,   7,   10,   1, 6, '_', 's',
        't', 'a', 'r', 't',  0, 0, 10,  4,
        1,   2,   0,   0x0b,
    };
    var memory: [1]u8 = undefined;
    var bad = good;
    for (0..bad.len) |i| {
        bad = good;
        bad[i] ^= 0xff;
        _ = execute(&bad, .{ .fuel = 1000 }, &memory);
    }
    try std.testing.expectEqual(vm.Trap.malformed, execute(good[0..7], .{}, &memory).trap);
}

test "arbitrary bytes fail closed" {
    var memory: [1]u8 = undefined;
    var bytes: [512]u8 = undefined;
    var seed: u64 = 0x4d595df4d0f33173;
    for (0..512) |_| {
        const len: usize = @intCast(seed % (bytes.len + 1));
        for (bytes[0..len]) |*byte| {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            byte.* = @truncate(seed >> 32);
        }
        _ = execute(bytes[0..len], .{ .fuel = 1000 }, &memory);
    }
}

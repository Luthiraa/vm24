const std = @import("std");

fn le(bytes: []const u8) u64 {
    var value: u64 = 0;
    for (bytes, 0..) |byte, shift| value |= @as(u64, byte) << @intCast(shift * 8);
    return value;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 3) return error.BadArguments;
    const dir = std.Io.Dir.cwd();
    const image = try dir.readFileAlloc(init.io, args[1], allocator, .limited(1 << 20));
    if (image.len < 64 or !std.mem.eql(u8, image[0..7], "\x7fELF\x02\x01\x01") or le(image[16..18]) != 3 or le(image[18..20]) != 62) return error.BadElf;

    const phoff: usize = @intCast(le(image[32..40]));
    const phentsize: usize = @intCast(le(image[54..56]));
    const phnum: usize = @intCast(le(image[56..58]));
    if (phentsize != 56 or phnum < 2 or phoff + phentsize * phnum > image.len) return error.BadElf;
    var end: usize = 0;
    var rx = false;
    var rw = false;
    for (0..phnum) |i| {
        const p = phoff + i * phentsize;
        if (le(image[p..][0..4]) != 1) continue;
        const flags = le(image[p..][4..8]);
        const offset: usize = @intCast(le(image[p..][8..16]));
        const vaddr: usize = @intCast(le(image[p..][16..24]));
        const filesz: usize = @intCast(le(image[p..][32..40]));
        const alignment = le(image[p..][48..56]);
        if (flags & 3 == 3 or alignment < 4096 or offset % 4096 != vaddr % 4096 or offset + filesz < offset) return error.BadElf;
        rx = rx or flags == 5;
        rw = rw or flags == 6;
        end = @max(end, offset + filesz);
    }
    if (!rx or !rw or end > 24_576) return error.BadElf;
    @memset(image[40..48], 0); // no section-header table
    @memset(image[58..64], 0);
    try dir.writeFile(init.io, .{
        .sub_path = args[2],
        .data = image[0..end],
        .flags = .{ .permissions = .fromMode(0o755) },
    });
}

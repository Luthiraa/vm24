// parse -> typecheck -> instantiate -> interpret. i32/i64 only.
const PAGE = 65536;

pub const Trap = enum(u8) { ok, malformed, unsupported, limit, runtime, exit };

pub const Limits = struct {
    fuel: u64 = 50_000_000,
    memory_pages: u32 = 1024,
    call_depth: u16 = 64,
    output_bytes: u64 = 1_048_576,
    input_bytes: u64 = 1_048_576,
};

pub const Outcome = struct { trap: Trap, code: u8 = 0 };

const MAX_TYPES = 255;
const MAX_FUNCS = 2048;
const MAX_IMPORTS = 32;
const MAX_EXPORTS = 128;
const MAX_GLOBALS = 128;
const MAX_CODES = MAX_FUNCS;
const MAX_ELEMS = 32;
const MAX_ELEM_FUNCS = 1024;
const MAX_DATA = 128;
const MAX_PARAMS = 32;
const MAX_LOCALS = 256;
const MAX_STACK = 4096;
const MAX_LABELS = 128;
const MAX_TABLE = 1024;
const MAX_IOVECS = 64;
const INVALID_FUNC: u16 = 0xffff;

const T = enum(u8) { i32, i64, bot }; // bot = unreachable code

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

const Cur = struct { // cursor over wasm bytes
    p: [*]const u8,
    e: [*]const u8,

    fn left(c: Cur) usize {
        return @intFromPtr(c.e) - @intFromPtr(c.p);
    }
    fn done(c: Cur) bool {
        return @intFromPtr(c.p) == @intFromPtr(c.e);
    }
    fn byte(c: *Cur) ?u8 {
        if (c.left() == 0) return null;
        const b = c.p[0];
        c.p += 1;
        return b;
    }
    fn u32leb(c: *Cur) ?u32 {
        var r: u32 = 0;
        var n: u3 = 0;
        while (n < 5) : (n += 1) {
            const b = c.byte() orelse return null;
            if (n == 4 and (b & 0xf0) != 0) return null;
            r |= @as(u32, b & 0x7f) << @intCast(@as(u6, n) * 7);
            if (b & 0x80 == 0) return r;
        }
        return null;
    }
    fn sleb(c: *Cur, comptime bits: u7) ?i64 {
        const max = (bits + 6) / 7;
        var r: u64 = 0;
        var shift: u7 = 0;
        var n: u8 = 0;
        var b: u8 = 0;
        while (n < max) : (n += 1) {
            b = c.byte() orelse return null;
            const payload = b & 0x7f;
            if (n + 1 == max) {
                const used: u3 = @intCast(bits - shift);
                const mask: u8 = @as(u8, 0x7f) << used;
                const extra = payload & mask;
                if (extra != 0 and extra != mask) return null;
            }
            r |= @as(u64, payload) << @intCast(shift);
            shift += 7;
            if (b & 0x80 == 0) {
                if (shift < bits and b & 0x40 != 0) r |= ~@as(u64, 0) << @intCast(shift);
                return @bitCast(r);
            }
        }
        return null;
    }
    fn i32leb(c: *Cur) ?i32 {
        return @truncate(c.sleb(32) orelse return null);
    }
    fn i64leb(c: *Cur) ?i64 {
        return c.sleb(64);
    }
    fn span(c: *Cur) ?Span {
        const n = c.u32leb() orelse return null;
        if (n > 255 or c.left() < n) return null;
        const s = Span{ .p = c.p, .n = @intCast(n) };
        c.p += n;
        return s;
    }
};

const Span = struct {
    p: [*]const u8,
    n: u8,
    fn bytes(s: Span) []const u8 {
        return s.p[0..s.n];
    }
};

fn valueType(b: u8) ?T {
    return switch (b) {
        0x7f => .i32,
        0x7e => .i64,
        else => null,
    };
}

const TypeRec = struct { nparams: u8, nresults: u8, params: [MAX_PARAMS]T, result: T };
const ImportRec = struct { module: Span, name: Span, ty: u8, host_id: u8 };
const ExportRec = struct { name: Span, kind: u8, idx: u16 };
const GlobalRec = struct { ty: T, mutable: bool, init: Span };
const CodeRec = struct { decl: [*]const u8, body: [*]const u8, end: [*]const u8, locals: u16 };
const ElemRec = struct { offset: Span, funcs: [MAX_ELEM_FUNCS]u16, n: u16 };
const DataRec = struct { offset: Span, data: [*]const u8, len: u32, active: bool };

const Mod = struct {
    types: [MAX_TYPES]TypeRec,
    ntypes: u8,
    func_types: [MAX_FUNCS]u8,
    nfuncs: u16,
    nimports: u8,
    imports: [MAX_IMPORTS]ImportRec,
    exports: [MAX_EXPORTS]ExportRec,
    nexports: u8,
    globals: [MAX_GLOBALS]GlobalRec,
    nglobals: u8,
    codes: [MAX_CODES]CodeRec,
    ncodes: u16,
    elems: [MAX_ELEMS]ElemRec,
    nelems: u8,
    datas: [MAX_DATA]DataRec,
    ndatas: u8,
    data_count: u32,
    memory_min: u32,
    memory_max: u32,
    table_min: u32,
    table_max: u32,
    start: u16,
    has_memory: bool,
    has_table: bool,
    has_start: bool,
    has_data_count: bool,
};

fn limits(c: *Cur) ?struct { min: u32, max: u32 } {
    const flag = c.byte() orelse return null;
    const min = c.u32leb() orelse return null;
    const max = switch (flag) {
        0 => @as(u32, 65536),
        1 => c.u32leb() orelse return null,
        else => return null,
    };
    if (max < min) return null;
    return .{ .min = min, .max = max };
}

fn constExpr(c: *Cur) ?Span {
    const begin = c.p;
    switch (c.byte() orelse return null) {
        0x41 => _ = c.i32leb() orelse return null,
        0x42 => _ = c.i64leb() orelse return null,
        else => return null,
    }
    if (c.byte() != 0x0b) return null;
    return .{ .p = begin, .n = @intCast(@intFromPtr(c.p) - @intFromPtr(begin)) };
}

fn parseModule(bytes: []const u8, m: *Mod) Trap {
    if (bytes.len < 8 or bytes.len > 4 * 1024 * 1024) return .malformed;
    if (!eql(bytes[0..4], "\x00asm")) return .malformed;
    if (!eql(bytes[4..8], &.{ 1, 0, 0, 0 })) return .unsupported;
    m.* = undefined;
    @memset(@as([*]u8, @ptrCast(m))[0..@sizeOf(Mod)], 0);
    var file = Cur{ .p = bytes.ptr + 8, .e = bytes.ptr + bytes.len };
    var last: u8 = 0;
    while (!file.done()) {
        const id = file.byte() orelse return .malformed;
        const size = file.u32leb() orelse return .malformed;
        if (file.left() < size) return .malformed;
        // custom (0) can repeat. data_count (12) has to come before code (10).
        const rank: u8 = switch (id) {
            0 => 0,
            1...9 => id,
            12 => 10,
            10 => 11,
            11 => 12,
            else => return .unsupported,
        };
        if (rank != 0 and rank <= last) return .malformed;
        if (rank != 0) last = rank;
        var c = Cur{ .p = file.p, .e = file.p + size };
        const t = parseSection(id, &c, m);
        if (t != .ok) return t;
        if (!c.done()) return .malformed;
        file.p = c.e;
    }
    if (m.ncodes != m.nfuncs - m.nimports) return .malformed;
    return finishModule(m);
}

fn parseSection(id: u8, c: *Cur, m: *Mod) Trap {
    if (id == 0) {
        c.p = c.e;
        return .ok;
    }
    const n = c.u32leb() orelse return .malformed;
    switch (id) {
        1 => { // types
            if (n > MAX_TYPES) return .limit;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                if (c.byte() != 0x60) return .malformed;
                const nparams = c.u32leb() orelse return .malformed;
                if (nparams > MAX_PARAMS) return .unsupported;
                var rec: TypeRec = .{ .nparams = @intCast(nparams), .nresults = 0, .params = undefined, .result = .i32 };
                var j: u32 = 0;
                while (j < nparams) : (j += 1) rec.params[j] = valueType(c.byte() orelse return .malformed) orelse return .unsupported;
                const nresults = c.u32leb() orelse return .malformed;
                if (nresults > 1) return .unsupported;
                rec.nresults = @intCast(nresults);
                if (nresults == 1) rec.result = valueType(c.byte() orelse return .malformed) orelse return .unsupported;
                m.types[m.ntypes] = rec;
                m.ntypes += 1;
            }
        },
        2 => { // imports
            if (n > MAX_IMPORTS) return .limit;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const module = c.span() orelse return .malformed;
                const name = c.span() orelse return .malformed;
                if (c.byte() != 0) return .unsupported;
                const ty = c.u32leb() orelse return .malformed;
                if (ty >= m.ntypes or m.nfuncs >= MAX_FUNCS) return .malformed;
                m.imports[m.nimports] = .{ .module = module, .name = name, .ty = @intCast(ty), .host_id = 0 };
                m.func_types[m.nfuncs] = @intCast(ty);
                m.nimports += 1;
                m.nfuncs += 1;
            }
        },
        3 => { // functions
            if (n > MAX_FUNCS - m.nfuncs) return .limit;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const ty = c.u32leb() orelse return .malformed;
                if (ty >= m.ntypes) return .malformed;
                m.func_types[m.nfuncs] = @intCast(ty);
                m.nfuncs += 1;
            }
        },
        4 => { // table
            if (n > 1 or m.has_table) return .unsupported;
            if (n == 1) {
                if (c.byte() != 0x70) return .unsupported;
                const lim = limits(c) orelse return .malformed;
                m.table_min = lim.min;
                m.table_max = lim.max;
                m.has_table = true;
            }
        },
        5 => { // memory
            if (n > 1 or m.has_memory) return .unsupported;
            if (n == 1) {
                const lim = limits(c) orelse return .malformed;
                m.memory_min = lim.min;
                m.memory_max = lim.max;
                m.has_memory = true;
            }
        },
        6 => { // globals
            if (n > MAX_GLOBALS) return .limit;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const ty = valueType(c.byte() orelse return .malformed) orelse return .unsupported;
                const mut = c.byte() orelse return .malformed;
                if (mut > 1) return .malformed;
                const init = constExpr(c) orelse return .malformed;
                m.globals[m.nglobals] = .{ .ty = ty, .mutable = mut == 1, .init = init };
                m.nglobals += 1;
            }
        },
        7 => { // exports
            if (n > MAX_EXPORTS) return .limit;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const name = c.span() orelse return .malformed;
                const kind = c.byte() orelse return .malformed;
                const idx = c.u32leb() orelse return .malformed;
                if (kind > 3 or idx > 0xffff) return .malformed;
                var j: u8 = 0;
                while (j < m.nexports) : (j += 1) if (eql(name.bytes(), m.exports[j].name.bytes())) return .malformed;
                m.exports[m.nexports] = .{ .name = name, .kind = kind, .idx = @intCast(idx) };
                m.nexports += 1;
            }
        },
        8 => { // start
            if (n >= m.nfuncs) return .malformed;
            m.start = @intCast(n);
            m.has_start = true;
        },
        9 => { // elements
            if (n > MAX_ELEMS) return .limit;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                if (c.u32leb() != 0) return .unsupported;
                const off = constExpr(c) orelse return .malformed;
                const count = c.u32leb() orelse return .malformed;
                if (count > MAX_ELEM_FUNCS) return .limit;
                var e = ElemRec{ .offset = off, .funcs = undefined, .n = @intCast(count) };
                var j: u32 = 0;
                while (j < count) : (j += 1) {
                    const f = c.u32leb() orelse return .malformed;
                    if (f >= m.nfuncs) return .malformed;
                    e.funcs[j] = @intCast(f);
                }
                m.elems[m.nelems] = e;
                m.nelems += 1;
            }
        },
        10 => { // code
            if (n > MAX_CODES) return .limit;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const size = c.u32leb() orelse return .malformed;
                if (size == 0 or c.left() < size) return .malformed;
                const end = c.p + size;
                const decl = c.p;
                const groups = c.u32leb() orelse return .malformed;
                var count: u32 = 0;
                var j: u32 = 0;
                while (j < groups) : (j += 1) {
                    const add = c.u32leb() orelse return .malformed;
                    _ = valueType(c.byte() orelse return .malformed) orelse return .unsupported;
                    const sum = @addWithOverflow(count, add);
                    if (sum[1] != 0 or sum[0] > MAX_LOCALS) return .limit;
                    count = sum[0];
                }
                if (@intFromPtr(c.p) >= @intFromPtr(end) or (end - 1)[0] != 0x0b) return .malformed;
                m.codes[m.ncodes] = .{ .decl = decl, .body = c.p, .end = end, .locals = @intCast(count) };
                m.ncodes += 1;
                c.p = end;
            }
        },
        11 => { // data
            if (n > MAX_DATA) return .limit;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const mode = c.u32leb() orelse return .malformed;
                if (mode > 2) return .unsupported;
                if (mode == 2 and c.u32leb() != 0) return .unsupported;
                const active = mode != 1;
                const off = if (active) constExpr(c) orelse return .malformed else Span{ .p = c.p, .n = 0 };
                const len = c.u32leb() orelse return .malformed;
                if (c.left() < len) return .malformed;
                m.datas[m.ndatas] = .{ .offset = off, .data = c.p, .len = len, .active = active };
                m.ndatas += 1;
                c.p += len;
            }
        },
        12 => { // data_count
            m.data_count = n;
            m.has_data_count = true;
        },
        else => return .unsupported,
    }
    return .ok;
}

fn signature(t: *const TypeRec, params: []const T, result: ?T) bool {
    if (t.nparams != params.len or t.nresults != @intFromBool(result != null)) return false;
    for (params, 0..) |x, i| if (t.params[i] != x) return false;
    return result == null or t.result == result.?;
}

fn sameSignature(a: *const TypeRec, b: *const TypeRec) bool {
    if (a.nparams != b.nparams or a.nresults != b.nresults or (a.nresults == 1 and a.result != b.result)) return false;
    var i: u8 = 0;
    while (i < a.nparams) : (i += 1) if (a.params[i] != b.params[i]) return false;
    return true;
}

const HostId = enum(u8) {
    proc_exit,
    fd_write,
    fd_read,
    args_sizes_get,
    args_get,
    environ_sizes_get,
    environ_get,
    random_get,
    clock_time_get,
    fd_fdstat_get,
    fd_close,
    sched_yield,
    denied_errno,
    denied_trap,
};

fn wasiId(name: []const u8, ty: *const TypeRec) HostId {
    if (eql(name, "proc_exit") and signature(ty, &.{.i32}, null)) return .proc_exit;
    if (eql(name, "fd_write") and signature(ty, &.{ .i32, .i32, .i32, .i32 }, .i32)) return .fd_write;
    if (eql(name, "fd_read") and signature(ty, &.{ .i32, .i32, .i32, .i32 }, .i32)) return .fd_read;
    if (eql(name, "args_sizes_get") and signature(ty, &.{ .i32, .i32 }, .i32)) return .args_sizes_get;
    if (eql(name, "args_get") and signature(ty, &.{ .i32, .i32 }, .i32)) return .args_get;
    if (eql(name, "environ_sizes_get") and signature(ty, &.{ .i32, .i32 }, .i32)) return .environ_sizes_get;
    if (eql(name, "environ_get") and signature(ty, &.{ .i32, .i32 }, .i32)) return .environ_get;
    if (eql(name, "random_get") and signature(ty, &.{ .i32, .i32 }, .i32)) return .random_get;
    if (eql(name, "clock_time_get") and signature(ty, &.{ .i32, .i64, .i32 }, .i32)) return .clock_time_get;
    if (eql(name, "fd_fdstat_get") and signature(ty, &.{ .i32, .i32 }, .i32)) return .fd_fdstat_get;
    if (eql(name, "fd_close") and signature(ty, &.{.i32}, .i32)) return .fd_close;
    if (eql(name, "sched_yield") and signature(ty, &.{}, .i32)) return .sched_yield;
    if (ty.nresults == 1 and ty.result == .i32) return .denied_errno;
    return .denied_trap;
}

fn bindImport(m: *Mod, imp: *ImportRec) bool {
    const module = imp.module.bytes();
    if (!eql(module, "wasi_snapshot_preview1") and !eql(module, "wasi_unstable")) return false;
    imp.host_id = @intFromEnum(wasiId(imp.name.bytes(), &m.types[imp.ty]));
    return true;
}

fn finishModule(m: *Mod) Trap {
    if (m.memory_min > m.memory_max or m.table_min > m.table_max) return .malformed;
    if (m.table_min > MAX_TABLE) return .limit;
    var i: u8 = 0;
    while (i < m.nimports) : (i += 1) if (!bindImport(m, &m.imports[i])) return .unsupported;
    i = 0;
    while (i < m.nexports) : (i += 1) {
        const e = m.exports[i];
        const good = switch (e.kind) {
            0 => e.idx < m.nfuncs,
            1 => e.idx == 0 and m.has_table,
            2 => e.idx == 0 and m.has_memory,
            3 => e.idx < m.nglobals,
            else => false,
        };
        if (!good) return .malformed;
    }
    if (m.has_start) {
        const t = &m.types[m.func_types[m.start]];
        if (t.nparams != 0 or t.nresults != 0) return .malformed;
    }
    if (m.nelems != 0 and !m.has_table) return .malformed;
    if (m.has_data_count and m.data_count != m.ndatas) return .malformed;
    i = 0;
    while (i < m.ndatas) : (i += 1) if (m.datas[i].active and !m.has_memory) return .malformed;
    return .ok;
}

const Ctrl = struct { kind: u8, height: u16, has: bool, ty: T, dead: bool, seen_else: bool };
var vstack: [MAX_STACK]T = undefined;
var vlocals: [MAX_LOCALS]T = undefined;
var vsp: usize = 0;

fn vpop(ctrl: *const Ctrl, want: T) bool {
    if (vsp == ctrl.height and ctrl.dead) return true;
    if (vsp <= ctrl.height) return false;
    vsp -= 1;
    return vstack[vsp] == want or vstack[vsp] == .bot;
}
fn vpopAny(ctrl: *const Ctrl) ?T {
    if (vsp == ctrl.height and ctrl.dead) return .bot;
    if (vsp <= ctrl.height) return null;
    vsp -= 1;
    return vstack[vsp];
}
fn vpush(t: T) bool {
    if (vsp >= MAX_STACK) return false;
    vstack[vsp] = t;
    vsp += 1;
    return true;
}
fn vun(ctrl: *const Ctrl, a: T, r: T) bool {
    return vpop(ctrl, a) and vpush(r);
}
fn vbin(ctrl: *const Ctrl, a: T, r: T) bool {
    return vpop(ctrl, a) and vpop(ctrl, a) and vpush(r);
}
fn blockType(c: *Cur) ?struct { has: bool, ty: T } {
    const b = c.byte() orelse return null;
    if (b == 0x40) return .{ .has = false, .ty = .i32 };
    return .{ .has = true, .ty = valueType(b) orelse return null };
}
fn labelType(x: *const Ctrl) ?T {
    return if (x.kind == 0x03 or !x.has) null else x.ty;
}
fn markDead(x: *Ctrl) void {
    vsp = x.height;
    x.dead = true;
}
fn vbranch(labels: []Ctrl, depth: u32, conditional: bool) bool {
    if (depth >= labels.len) return false;
    const target = &labels[labels.len - 1 - depth];
    const top = &labels[labels.len - 1];
    if (labelType(target)) |ty| {
        if (!vpop(top, ty)) return false;
        if (conditional and !vpush(ty)) return false;
    }
    if (!conditional) markDead(top);
    return true;
}

fn validateBody(m: *const Mod, fidx: u16) Trap {
    const code = m.codes[fidx - m.nimports];
    const ft = &m.types[m.func_types[fidx]];
    if (@as(u16, ft.nparams) + code.locals > MAX_LOCALS) return .limit;
    var nl: usize = 0;
    while (nl < ft.nparams) : (nl += 1) vlocals[nl] = ft.params[nl];
    var dc = Cur{ .p = code.decl, .e = code.body };
    const groups = dc.u32leb() orelse return .malformed;
    var g: u32 = 0;
    while (g < groups) : (g += 1) {
        const count = dc.u32leb() orelse return .malformed;
        const ty = valueType(dc.byte() orelse return .malformed) orelse return .unsupported;
        var j: u32 = 0;
        while (j < count) : (j += 1) {
            if (nl >= MAX_LOCALS) return .limit;
            vlocals[nl] = ty;
            nl += 1;
        }
    }
    if (!dc.done()) return .malformed;
    var labels: [MAX_LABELS]Ctrl = undefined;
    labels[0] = .{ .kind = 0xff, .height = 0, .has = ft.nresults == 1, .ty = ft.result, .dead = false, .seen_else = false };
    var lp: usize = 1;
    vsp = 0;
    var c = Cur{ .p = code.body, .e = code.end };
    while (!c.done()) {
        const op = c.byte() orelse return .malformed;
        var top = &labels[lp - 1];
        switch (op) {
            0x00 => markDead(top), // unreachable
            0x01 => {}, // nop
            0x02, 0x03, 0x04 => { // block, loop, if
                if (op == 0x04 and !vpop(top, .i32)) return .malformed;
                const bt = blockType(&c) orelse return .unsupported;
                if (lp >= MAX_LABELS) return .limit;
                labels[lp] = .{ .kind = op, .height = @intCast(vsp), .has = bt.has, .ty = bt.ty, .dead = false, .seen_else = false };
                lp += 1;
            },
            0x05 => { // else
                if (top.kind != 0x04 or top.seen_else) return .malformed;
                if (top.has and !vpop(top, top.ty)) return .malformed;
                if (vsp != top.height) return .malformed;
                vsp = top.height;
                top.dead = false;
                top.seen_else = true;
            },
            0x0b => { // end
                if (top.has and !vpop(top, top.ty)) return .malformed;
                if (vsp != top.height or (top.kind == 0x04 and top.has and !top.seen_else)) return .malformed;
                const has = top.has;
                const ty = top.ty;
                lp -= 1;
                if (lp == 0) return if (c.done()) .ok else .malformed;
                if (has and !vpush(ty)) return .limit;
            },
            0x0c, 0x0d => { // br, br_if
                const depth = c.u32leb() orelse return .malformed;
                if (op == 0x0d and !vpop(top, .i32)) return .malformed;
                if (!vbranch(labels[0..lp], depth, op == 0x0d)) return .malformed;
            },
            0x0e => { // br_table
                const count = c.u32leb() orelse return .malformed;
                if (!vpop(top, .i32)) return .malformed;
                var expected: ?T = null;
                var has_expected = false;
                var j: u32 = 0;
                while (j <= count) : (j += 1) {
                    const depth = c.u32leb() orelse return .malformed;
                    if (depth >= lp) return .malformed;
                    const lt = labelType(&labels[lp - 1 - depth]);
                    if (j == 0) {
                        expected = lt;
                        has_expected = lt != null;
                    } else if (has_expected != (lt != null) or (lt != null and expected.? != lt.?)) return .malformed;
                }
                if (expected) |ty| if (!vpop(top, ty)) return .malformed;
                markDead(top);
            },
            0x0f => if (!vbranch(labels[0..lp], @intCast(lp - 1), false)) return .malformed, // return
            0x10 => { // call
                const f = c.u32leb() orelse return .malformed;
                if (f >= m.nfuncs) return .malformed;
                const t = &m.types[m.func_types[f]];
                var j: usize = t.nparams;
                while (j != 0) {
                    j -= 1;
                    if (!vpop(top, t.params[j])) return .malformed;
                }
                if (t.nresults == 1 and !vpush(t.result)) return .limit;
            },
            0x11 => { // call_indirect
                const ty = c.u32leb() orelse return .malformed;
                if (ty >= m.ntypes or c.byte() != 0 or !m.has_table or !vpop(top, .i32)) return .malformed;
                const t = &m.types[ty];
                var j: usize = t.nparams;
                while (j != 0) {
                    j -= 1;
                    if (!vpop(top, t.params[j])) return .malformed;
                }
                if (t.nresults == 1 and !vpush(t.result)) return .limit;
            },
            0x1a => if (vpopAny(top) == null) return .malformed, // drop
            0x1b => { // select
                if (!vpop(top, .i32)) return .malformed;
                const b = vpopAny(top) orelse return .malformed;
                const a = vpopAny(top) orelse return .malformed;
                if (a != .bot and b != .bot and a != b) return .malformed;
                if (!vpush(if (a == .bot) b else a)) return .limit;
            },
            0x20, 0x21, 0x22 => { // local.get/set/tee
                const x = c.u32leb() orelse return .malformed;
                if (x >= nl) return .malformed;
                if (op != 0x20 and !vpop(top, vlocals[x])) return .malformed;
                if (op != 0x21 and !vpush(vlocals[x])) return .limit;
            },
            0x23, 0x24 => { // global.get/set
                const x = c.u32leb() orelse return .malformed;
                if (x >= m.nglobals or (op == 0x24 and !m.globals[x].mutable)) return .malformed;
                if (op == 0x23) {
                    if (!vpush(m.globals[x].ty)) return .limit;
                } else if (!vpop(top, m.globals[x].ty)) return .malformed;
            },
            0x28...0x3e => { // load/store
                if (!m.has_memory) return .malformed;
                const alignment = c.u32leb() orelse return .malformed;
                _ = c.u32leb() orelse return .malformed;
                if (op == 0x2a or op == 0x2b or op == 0x38 or op == 0x39) return .unsupported;
                const natural: u32 = switch (op) {
                    0x28, 0x36 => 2,
                    0x29, 0x37 => 3,
                    0x2e, 0x2f, 0x32, 0x33, 0x3b, 0x3d => 1,
                    0x34, 0x35, 0x3e => 2,
                    else => 0,
                };
                if (alignment > natural) return .malformed;
                const ty: T = if (op == 0x29 or (op >= 0x30 and op <= 0x35) or op == 0x37 or (op >= 0x3c and op <= 0x3e)) .i64 else .i32;
                if (op >= 0x36) {
                    if (!vpop(top, ty) or !vpop(top, .i32)) return .malformed;
                } else {
                    if (!vpop(top, .i32) or !vpush(ty)) return .malformed;
                }
            },
            0x3f => { // memory.size
                if (!m.has_memory or c.byte() != 0 or !vpush(.i32)) return .malformed;
            },
            0x40 => { // memory.grow
                if (!m.has_memory or c.byte() != 0 or !vun(top, .i32, .i32)) return .malformed;
            },
            0x41 => { // i32.const
                _ = c.i32leb() orelse return .malformed;
                if (!vpush(.i32)) return .limit;
            },
            0x42 => { // i64.const
                _ = c.i64leb() orelse return .malformed;
                if (!vpush(.i64)) return .limit;
            },
            0x45, 0x67...0x69 => if (!vun(top, .i32, .i32)) return .malformed, // i32 unop
            0x46...0x4f, 0x6a...0x78 => if (!vbin(top, .i32, .i32)) return .malformed, // i32 binop
            0x50 => if (!vun(top, .i64, .i32)) return .malformed, // i64.eqz
            0x51...0x5a => if (!vbin(top, .i64, .i32)) return .malformed, // i64 relop
            0x79...0x7b => if (!vun(top, .i64, .i64)) return .malformed, // i64 unop
            0x7c...0x8a => if (!vbin(top, .i64, .i64)) return .malformed, // i64 binop
            0xa7 => if (!vun(top, .i64, .i32)) return .malformed, // i32.wrap_i64
            0xac, 0xad => if (!vun(top, .i32, .i64)) return .malformed, // i64.extend_i32
            0xc0, 0xc1 => if (!vun(top, .i32, .i32)) return .malformed, // i32.extend
            0xc2...0xc4 => if (!vun(top, .i64, .i64)) return .malformed, // i64.extend
            0xfc => { // bulk memory
                const sub = c.u32leb() orelse return .malformed;
                if (!m.has_memory) return .malformed;
                switch (sub) {
                    8 => { // memory.init
                        const data = c.u32leb() orelse return .malformed;
                        if (!m.has_data_count or data >= m.ndatas or c.u32leb() != 0) return .malformed;
                        if (!vpop(top, .i32) or !vpop(top, .i32) or !vpop(top, .i32)) return .malformed;
                    },
                    9 => { // data.drop
                        const data = c.u32leb() orelse return .malformed;
                        if (!m.has_data_count or data >= m.ndatas) return .malformed;
                    },
                    10 => { // memory.copy
                        if (c.u32leb() != 0 or c.u32leb() != 0) return .malformed;
                        if (!vpop(top, .i32) or !vpop(top, .i32) or !vpop(top, .i32)) return .malformed;
                    },
                    11 => { // memory.fill
                        if (c.u32leb() != 0) return .malformed;
                        if (!vpop(top, .i32) or !vpop(top, .i32) or !vpop(top, .i32)) return .malformed;
                    },
                    else => return .unsupported,
                }
            },
            else => return .unsupported,
        }
    }
    return .malformed;
}

fn validateModule(m: *const Mod) Trap {
    var f = m.nimports;
    while (f < m.nfuncs) : (f += 1) {
        const t = validateBody(m, f);
        if (t != .ok) return t;
    }
    return .ok;
}

var stack: [MAX_STACK]u64 = undefined;
var sp: usize = 0;
var globals: [MAX_GLOBALS]u64 = undefined;
var table: [MAX_TABLE]u16 = undefined;
var data_dropped: [MAX_DATA]bool = undefined;
var memory: [*]u8 = undefined;
var memory_len: usize = 0;
var memory_max: usize = 0;

fn push(x: u64) bool {
    if (sp >= MAX_STACK) return false;
    stack[sp] = x;
    sp += 1;
    return true;
}
fn pop() ?u64 {
    if (sp == 0) return null;
    sp -= 1;
    return stack[sp];
}
fn pair() ?struct { a: u64, b: u64 } {
    const b = pop() orelse return null;
    const a = pop() orelse return null;
    return .{ .a = a, .b = b };
}
fn addr(base: u32, off: u32, n: usize) ?usize {
    const a = @as(u64, base) + off;
    if (a + n > memory_len) return null;
    return @intCast(a);
}
fn load(base: u32, off: u32, n: usize) ?u64 {
    const a = addr(base, off, n) orelse return null;
    var r: u64 = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) r |= @as(u64, memory[a + i]) << @intCast(i * 8);
    return r;
}
fn store(base: u32, off: u32, x: u64, n: usize) bool {
    const a = addr(base, off, n) orelse return false;
    var i: usize = 0;
    while (i < n) : (i += 1) memory[a + i] = @truncate(x >> @intCast(i * 8));
    return true;
}
fn put32(at: u32, x: u32) bool {
    return store(at, 0, x, 4);
}

fn iovecAt(iovs: u32, i: u32) ?struct { ptr: u32, len: u32 } {
    const base = iovs +% i *% 8;
    const ptr = @as(u32, @truncate(load(base, 0, 4) orelse return null));
    const len = @as(u32, @truncate(load(base, 4, 4) orelse return null));
    return .{ .ptr = ptr, .len = len };
}
fn charge(lim: *Limits) bool {
    if (lim.fuel == 0) return false;
    lim.fuel -= 1;
    return true;
}

fn chargeBytes(lim: *Limits, n: u32) bool {
    const cost = n / 64;
    if (lim.fuel < cost) {
        lim.fuel = 0;
        return false;
    }
    lim.fuel -= cost;
    return true;
}

fn evalConst(s: Span, want: T) ?u64 {
    var c = Cur{ .p = s.p, .e = s.p + s.n };
    const op = c.byte() orelse return null;
    const value: u64 = switch (op) {
        0x41 => @as(u32, @bitCast(c.i32leb() orelse return null)),
        0x42 => @bitCast(c.i64leb() orelse return null),
        else => return null,
    };
    if (c.byte() != 0x0b or !c.done()) return null;
    if ((op == 0x41) != (want == .i32)) return null;
    return value;
}

fn instantiate(m: *const Mod, lim: Limits, backing: []u8) Trap {
    if (m.memory_min > lim.memory_pages) return .limit;
    const max_pages = @min(m.memory_max, lim.memory_pages);
    if (@as(u64, max_pages) * PAGE > backing.len) return .limit;
    memory = backing.ptr;
    memory_len = @as(usize, m.memory_min) * PAGE;
    memory_max = @as(usize, max_pages) * PAGE;
    @memset(backing[0..memory_len], 0);
    @memset(table[0..], INVALID_FUNC);
    var i: u8 = 0;
    while (i < m.nglobals) : (i += 1) globals[i] = evalConst(m.globals[i].init, m.globals[i].ty) orelse return .malformed;
    i = 0;
    while (i < m.nelems) : (i += 1) {
        const e = m.elems[i];
        const off = @as(u32, @truncate(evalConst(e.offset, .i32) orelse return .malformed));
        if (@as(u64, off) + e.n > m.table_min or @as(u64, off) + e.n > MAX_TABLE) return .runtime;
        var j: u16 = 0;
        while (j < e.n) : (j += 1) table[off + j] = e.funcs[j];
    }
    i = 0;
    while (i < m.ndatas) : (i += 1) {
        const d = m.datas[i];
        data_dropped[i] = d.active;
        if (!d.active) continue;
        const off = @as(u32, @truncate(evalConst(d.offset, .i32) orelse return .malformed));
        const a = addr(off, 0, d.len) orelse return .runtime;
        @memcpy(memory[a..][0..d.len], d.data[0..d.len]);
    }
    return .ok;
}

const Label = struct { kind: u8, arity: u8, height: u16, cont: [*]const u8 };
const BlockPos = struct { else_at: ?[*]const u8, end_at: [*]const u8 };

fn skipInstruction(c: *Cur) ?u8 {
    const op = c.byte() orelse return null;
    switch (op) {
        0x02, 0x03, 0x04 => _ = blockType(c) orelse return null,
        0x0c, 0x0d, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24 => _ = c.u32leb() orelse return null,
        0x0e => {
            const n = c.u32leb() orelse return null;
            var i: u32 = 0;
            while (i <= n) : (i += 1) _ = c.u32leb() orelse return null;
        },
        0x11 => {
            _ = c.u32leb() orelse return null;
            if (c.byte() != 0) return null;
        },
        0x28...0x3e => {
            _ = c.u32leb() orelse return null;
            _ = c.u32leb() orelse return null;
        },
        0x3f, 0x40 => if (c.byte() != 0) return null,
        0x41 => _ = c.i32leb() orelse return null,
        0x42 => _ = c.i64leb() orelse return null,
        0xfc => {
            const sub = c.u32leb() orelse return null;
            switch (sub) {
                8, 10 => {
                    _ = c.u32leb() orelse return null;
                    _ = c.u32leb() orelse return null;
                },
                9, 11 => _ = c.u32leb() orelse return null,
                else => return null,
            }
        },
        else => {},
    }
    return op;
}

fn findBlock(begin: [*]const u8, end: [*]const u8, lim: *Limits) ?BlockPos {
    var c = Cur{ .p = begin, .e = end };
    var depth: u16 = 1;
    var else_at: ?[*]const u8 = null;
    while (!c.done()) {
        if (!charge(lim)) return null;
        const op = skipInstruction(&c) orelse return null;
        switch (op) {
            0x02, 0x03, 0x04 => depth += 1,
            0x05 => if (depth == 1) {
                else_at = c.p;
            },
            0x0b => {
                depth -= 1;
                if (depth == 0) return .{ .else_at = else_at, .end_at = c.p };
            },
            else => {},
        }
    }
    return null;
}

fn doBranch(labels: []Label, depth: u32, c: *Cur, lp: *usize) Trap {
    if (depth >= labels.len) return .runtime;
    const target_index = labels.len - 1 - depth;
    const target = labels[target_index];
    var result: u64 = 0;
    if (target.arity == 1) result = pop() orelse return .runtime;
    if (sp < target.height) return .runtime;
    sp = target.height;
    if (target.arity == 1 and !push(result)) return .limit;
    if (target.kind == 0x03) {
        lp.* = target_index + 1;
    } else {
        lp.* = target_index;
    }
    c.p = target.cont;
    return .ok;
}

fn hostCall(host: anytype, id: HostId, args: []const u64, lim: *Limits, out: *u64, exit_code: *u8) Trap {
    const ESUCCESS: u64 = 0;
    const EBADF: u64 = 8;
    const EFAULT: u64 = 21;
    const EINVAL: u64 = 28;
    out.* = ESUCCESS;
    switch (id) {
        .proc_exit => {
            exit_code.* = @truncate(args[0]);
            return .exit;
        },
        .fd_write => {
            const fd: u32 = @truncate(args[0]);
            if ((fd != 1 and fd != 2) or host.closed & (@as(u8, 1) << @intCast(fd)) != 0) {
                out.* = EBADF;
                return .ok;
            }
            const iovs: u32 = @truncate(args[1]);
            const count: u32 = @truncate(args[2]);
            if (count > MAX_IOVECS) {
                out.* = EINVAL;
                return .ok;
            }
            var total: u32 = 0;
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const vec = iovecAt(iovs, i) orelse {
                    out.* = EFAULT;
                    return .ok;
                };
                const at = addr(vec.ptr, 0, vec.len) orelse {
                    out.* = EFAULT;
                    return .ok;
                };
                if (host.output_used + vec.len > lim.output_bytes) return .limit;
                if (!host.write(fd, memory[at..][0..vec.len])) {
                    out.* = EBADF;
                    return .ok;
                }
                host.output_used += vec.len;
                total +%= vec.len;
            }
            if (!put32(@truncate(args[3]), total)) out.* = EFAULT;
        },
        .fd_read => {
            if (@as(u32, @truncate(args[0])) != 0 or host.closed & 1 != 0) {
                out.* = EBADF;
                return .ok;
            }
            const iovs: u32 = @truncate(args[1]);
            const count: u32 = @truncate(args[2]);
            if (count > MAX_IOVECS) {
                out.* = EINVAL;
                return .ok;
            }
            var total: u32 = 0;
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                const vec = iovecAt(iovs, i) orelse {
                    out.* = EFAULT;
                    return .ok;
                };
                var len = vec.len;
                const left = lim.input_bytes -| host.input_used;
                if (len > left) len = @intCast(left);
                const at = addr(vec.ptr, 0, len) orelse {
                    out.* = EFAULT;
                    return .ok;
                };
                const got = host.read(memory[at..][0..len]);
                if (got < 0) {
                    out.* = EBADF;
                    return .ok;
                }
                host.input_used += @intCast(got);
                total += @intCast(got);
                if (got < len) break;
            }
            if (!put32(@truncate(args[3]), total)) out.* = EFAULT;
        },
        .args_sizes_get => {
            const count = host.argCount();
            if (count > 128) return .limit;
            var bytes: usize = 0;
            var i: usize = 0;
            while (i < count) : (i += 1) bytes += (host.arg(i) orelse return .limit).len + 1;
            if (bytes > lim.input_bytes or !put32(@truncate(args[0]), @intCast(count)) or !put32(@truncate(args[1]), @intCast(bytes))) out.* = EFAULT;
        },
        .args_get => {
            const count = host.argCount();
            if (count > 128) return .limit;
            var ptrs: u32 = @truncate(args[0]);
            var buf: u32 = @truncate(args[1]);
            var i: usize = 0;
            while (i < count) : (i += 1) {
                const arg = host.arg(i) orelse return .limit;
                if (!put32(ptrs, buf)) {
                    out.* = EFAULT;
                    return .ok;
                }
                const at = addr(buf, 0, arg.len + 1) orelse {
                    out.* = EFAULT;
                    return .ok;
                };
                @memcpy(memory[at..][0..arg.len], arg);
                memory[at + arg.len] = 0;
                ptrs +%= 4;
                buf +%= @intCast(arg.len + 1);
            }
        },
        .environ_sizes_get => if (!put32(@truncate(args[0]), 0) or !put32(@truncate(args[1]), 0)) {
            out.* = EFAULT;
        },
        .environ_get => {},
        .random_get => {
            const len: u32 = @truncate(args[1]);
            const at = addr(@truncate(args[0]), 0, len) orelse {
                out.* = EFAULT;
                return .ok;
            };
            if (!host.random(memory[at..][0..len])) out.* = EINVAL;
        },
        .clock_time_get => {
            const ns = host.clock(@truncate(args[0])) orelse {
                out.* = EINVAL;
                return .ok;
            };
            if (!store(@truncate(args[2]), 0, ns, 8)) out.* = EFAULT;
        },
        .fd_fdstat_get => {
            const fd: u32 = @truncate(args[0]);
            if (fd > 2 or host.closed & (@as(u8, 1) << @intCast(fd)) != 0) {
                out.* = EBADF;
                return .ok;
            }
            const at = addr(@truncate(args[1]), 0, 24) orelse {
                out.* = EFAULT;
                return .ok;
            };
            @memset(memory[at..][0..24], 0);
            memory[at] = 2;
        },
        .fd_close => {
            const fd: u32 = @truncate(args[0]);
            if (fd > 2 or host.closed & (@as(u8, 1) << @intCast(fd)) != 0) out.* = EBADF else host.closed |= @as(u8, 1) << @intCast(fd);
        },
        .sched_yield => {},
        .denied_errno => out.* = 76, // ENOTCAPABLE
        .denied_trap => return .unsupported,
    }
    return .ok;
}

fn callImport(m: *const Mod, fidx: u16, lim: *Limits, host: anytype, exit_code: *u8) Trap {
    const imp = &m.imports[fidx];
    const ft = &m.types[imp.ty];
    if (sp < ft.nparams) return .runtime;
    const base = sp - ft.nparams;
    var result: u64 = 0;
    const t = hostCall(host, @enumFromInt(imp.host_id), stack[base..sp], lim, &result, exit_code);
    sp = base;
    if (t != .ok) return t;
    if (ft.nresults == 1 and !push(result)) return .limit;
    return .ok;
}

fn execNumber(op: u8) Trap {
    if (op == 0x45) return if (push(@intFromBool((pop() orelse return .runtime) & 0xffffffff == 0))) .ok else .limit; // i32.eqz
    if (op == 0x50) return if (push(@intFromBool((pop() orelse return .runtime) == 0))) .ok else .limit; // i64.eqz
    if (op >= 0x67 and op <= 0x69) { // i32 clz/ctz/popcnt
        const a: u32 = @truncate(pop() orelse return .runtime);
        const r: u32 = switch (op) {
            0x67 => @clz(a),
            0x68 => @ctz(a),
            else => @popCount(a),
        };
        return if (push(r)) .ok else .limit;
    }
    if (op >= 0x79 and op <= 0x7b) { // i64 clz/ctz/popcnt
        const a = pop() orelse return .runtime;
        const r: u64 = switch (op) {
            0x79 => @clz(a),
            0x7a => @ctz(a),
            else => @popCount(a),
        };
        return if (push(r)) .ok else .limit;
    }
    if (op >= 0xc0 and op <= 0xc4) { // sign-extend
        const a = pop() orelse return .runtime;
        const shift: u6 = switch (op) {
            0xc0, 0xc2 => 56,
            0xc1, 0xc3 => 48,
            else => 32,
        };
        const signed: u64 = @bitCast(@as(i64, @bitCast(a << shift)) >> shift);
        return if (push(if (op <= 0xc1) @as(u32, @truncate(signed)) else signed)) .ok else .limit;
    }
    const x = pair() orelse return .runtime;
    var r: u64 = 0;
    if (op >= 0x46 and op <= 0x4f) { // i32 relop
        const a: u32 = @truncate(x.a);
        const b: u32 = @truncate(x.b);
        const ai: i32 = @bitCast(a);
        const bi: i32 = @bitCast(b);
        r = @intFromBool(switch (op) {
            0x46 => a == b,
            0x47 => a != b,
            0x48 => ai < bi,
            0x49 => a < b,
            0x4a => ai > bi,
            0x4b => a > b,
            0x4c => ai <= bi,
            0x4d => a <= b,
            0x4e => ai >= bi,
            else => a >= b,
        });
    } else if (op >= 0x51 and op <= 0x5a) { // i64 relop
        const ai: i64 = @bitCast(x.a);
        const bi: i64 = @bitCast(x.b);
        r = @intFromBool(switch (op) {
            0x51 => x.a == x.b,
            0x52 => x.a != x.b,
            0x53 => ai < bi,
            0x54 => x.a < x.b,
            0x55 => ai > bi,
            0x56 => x.a > x.b,
            0x57 => ai <= bi,
            0x58 => x.a <= x.b,
            0x59 => ai >= bi,
            else => x.a >= x.b,
        });
    } else if (op >= 0x6a and op <= 0x78) { // i32 binop
        const a: u32 = @truncate(x.a);
        const b: u32 = @truncate(x.b);
        const ai: i32 = @bitCast(a);
        const bi: i32 = @bitCast(b);
        r = switch (op) {
            0x6a => a +% b,
            0x6b => a -% b,
            0x6c => a *% b,
            0x6d => if (b == 0 or (a == 0x80000000 and b == 0xffffffff)) return .runtime else @as(u32, @bitCast(@divTrunc(ai, bi))),
            0x6e => if (b == 0) return .runtime else a / b,
            0x6f => if (b == 0) return .runtime else if (a == 0x80000000 and b == 0xffffffff) 0 else @as(u32, @bitCast(@rem(ai, bi))),
            0x70 => if (b == 0) return .runtime else a % b,
            0x71 => a & b,
            0x72 => a | b,
            0x73 => a ^ b,
            0x74 => a << @intCast(b & 31),
            0x75 => @as(u32, @bitCast(ai >> @intCast(b & 31))),
            0x76 => a >> @intCast(b & 31),
            0x77 => (a << @intCast(b & 31)) | (a >> @intCast((0 -% b) & 31)),
            else => (a >> @intCast(b & 31)) | (a << @intCast((0 -% b) & 31)),
        };
    } else { // i64 binop
        const ai: i64 = @bitCast(x.a);
        const bi: i64 = @bitCast(x.b);
        r = switch (op) {
            0x7c => x.a +% x.b,
            0x7d => x.a -% x.b,
            0x7e => x.a *% x.b,
            0x7f => if (x.b == 0 or (x.a == 0x8000000000000000 and x.b == 0xffffffffffffffff)) return .runtime else @bitCast(@divTrunc(ai, bi)),
            0x80 => if (x.b == 0) return .runtime else x.a / x.b,
            0x81 => if (x.b == 0) return .runtime else if (x.a == 0x8000000000000000 and x.b == 0xffffffffffffffff) 0 else @bitCast(@rem(ai, bi)),
            0x82 => if (x.b == 0) return .runtime else x.a % x.b,
            0x83 => x.a & x.b,
            0x84 => x.a | x.b,
            0x85 => x.a ^ x.b,
            0x86 => x.a << @intCast(x.b & 63),
            0x87 => @bitCast(ai >> @intCast(x.b & 63)),
            0x88 => x.a >> @intCast(x.b & 63),
            0x89 => (x.a << @intCast(x.b & 63)) | (x.a >> @intCast((0 -% x.b) & 63)),
            else => (x.a >> @intCast(x.b & 63)) | (x.a << @intCast((0 -% x.b) & 63)),
        };
    }
    return if (push(r)) .ok else .limit;
}

fn runFunc(m: *const Mod, fidx: u16, lim: *Limits, host: anytype, depth: u16, exit_code: *u8) Trap {
    if (depth >= lim.call_depth or !charge(lim)) return .limit;
    if (fidx >= m.nfuncs) return .runtime;
    if (fidx < m.nimports) return callImport(m, fidx, lim, host, exit_code);
    const code = m.codes[fidx - m.nimports];
    const ft = &m.types[m.func_types[fidx]];
    if (sp < ft.nparams) return .runtime;
    const base = sp - ft.nparams;
    var locals: [MAX_LOCALS]u64 = .{0} ** MAX_LOCALS;
    var i: usize = 0;
    while (i < ft.nparams) : (i += 1) locals[i] = stack[base + i];
    sp = base;
    var labels: [MAX_LABELS]Label = undefined;
    labels[0] = .{ .kind = 0xff, .arity = ft.nresults, .height = @intCast(sp), .cont = code.end };
    var lp: usize = 1;
    var c = Cur{ .p = code.body, .e = code.end };
    while (!c.done()) {
        if (!charge(lim)) return .limit;
        const op = c.byte() orelse return .runtime;
        switch (op) {
            0x00 => return .runtime, // unreachable
            0x01 => {}, // nop
            0x02, 0x03, 0x04 => { // block, loop, if
                const cond = if (op == 0x04) pop() orelse return .runtime else 1;
                const bt = blockType(&c) orelse return .runtime;
                const pos = findBlock(c.p, c.e, lim) orelse return if (lim.fuel == 0) .limit else .runtime;
                if (lp >= MAX_LABELS) return .limit;
                labels[lp] = .{ .kind = op, .arity = if (op == 0x03) 0 else @intFromBool(bt.has), .height = @intCast(sp), .cont = if (op == 0x03) c.p else pos.end_at };
                lp += 1;
                if (op == 0x04 and @as(u32, @truncate(cond)) == 0) {
                    if (pos.else_at) |at| c.p = at else {
                        lp -= 1;
                        c.p = pos.end_at;
                    }
                }
            },
            0x05 => { // else
                const t = doBranch(labels[0..lp], 0, &c, &lp);
                if (t != .ok) return t;
            },
            0x0b => { // end
                const lab = labels[lp - 1];
                var result: u64 = 0;
                if (lab.arity == 1) result = pop() orelse return .runtime;
                if (sp < lab.height) return .runtime;
                sp = lab.height;
                if (lab.arity == 1 and !push(result)) return .limit;
                lp -= 1;
                if (lp == 0) return .ok;
            },
            0x0c, 0x0d => { // br, br_if
                const d = c.u32leb() orelse return .runtime;
                const take = op == 0x0c or @as(u32, @truncate(pop() orelse return .runtime)) != 0;
                if (take) {
                    const t = doBranch(labels[0..lp], d, &c, &lp);
                    if (t != .ok) return t;
                    if (lp == 0) return .ok;
                }
            },
            0x0e => { // br_table
                const count = c.u32leb() orelse return .runtime;
                const pick: u32 = @truncate(pop() orelse return .runtime);
                var chosen: u32 = 0;
                var j: u32 = 0;
                while (j <= count) : (j += 1) {
                    const d = c.u32leb() orelse return .runtime;
                    if (j == @min(pick, count)) chosen = d;
                }
                const t = doBranch(labels[0..lp], chosen, &c, &lp);
                if (t != .ok) return t;
                if (lp == 0) return .ok;
            },
            0x0f => { // return
                const t = doBranch(labels[0..lp], @intCast(lp - 1), &c, &lp);
                if (t != .ok) return t;
                return .ok;
            },
            0x10 => { // call
                const f = c.u32leb() orelse return .runtime;
                if (f >= m.nfuncs) return .runtime;
                const t = runFunc(m, @intCast(f), lim, host, depth + 1, exit_code);
                if (t != .ok) return t;
            },
            0x11 => { // call_indirect
                const ty = c.u32leb() orelse return .runtime;
                if (c.byte() != 0) return .runtime;
                const at: u32 = @truncate(pop() orelse return .runtime);
                if (at >= m.table_min or at >= MAX_TABLE) return .runtime;
                const f = table[at];
                if (f == INVALID_FUNC or f >= m.nfuncs or !sameSignature(&m.types[m.func_types[f]], &m.types[ty])) return .runtime;
                const t = runFunc(m, f, lim, host, depth + 1, exit_code);
                if (t != .ok) return t;
            },
            0x1a => _ = pop() orelse return .runtime, // drop
            0x1b => { // select
                const cond = pop() orelse return .runtime;
                const b = pop() orelse return .runtime;
                const a = pop() orelse return .runtime;
                if (!push(if (cond != 0) a else b)) return .limit;
            },
            0x20, 0x21, 0x22 => { // local.get/set/tee
                const x = c.u32leb() orelse return .runtime;
                if (x >= MAX_LOCALS) return .runtime;
                if (op == 0x20) {
                    if (!push(locals[x])) return .limit;
                } else if (op == 0x21) {
                    locals[x] = pop() orelse return .runtime;
                } else {
                    if (sp == 0) return .runtime;
                    locals[x] = stack[sp - 1];
                }
            },
            0x23 => { // global.get
                const x = c.u32leb() orelse return .runtime;
                if (x >= m.nglobals or !push(globals[x])) return .runtime;
            },
            0x24 => { // global.set
                const x = c.u32leb() orelse return .runtime;
                if (x >= m.nglobals or !m.globals[x].mutable) return .runtime;
                globals[x] = pop() orelse return .runtime;
            },
            0x28...0x35 => { // load
                _ = c.u32leb() orelse return .runtime;
                const off = c.u32leb() orelse return .runtime;
                const base_addr: u32 = @truncate(pop() orelse return .runtime);
                const n: usize = switch (op) {
                    0x28, 0x34, 0x35 => 4,
                    0x29 => 8,
                    0x2e, 0x2f, 0x32, 0x33 => 2,
                    else => 1,
                };
                var value = load(base_addr, off, n) orelse return .runtime;
                const signed = op == 0x2c or op == 0x2e or op == 0x30 or op == 0x32 or op == 0x34;
                if (signed and n < 8) {
                    const shift: u6 = @intCast(64 - n * 8);
                    value = @bitCast(@as(i64, @bitCast(value << shift)) >> shift);
                }
                if (!push(value)) return .limit;
            },
            0x36...0x3e => { // store
                _ = c.u32leb() orelse return .runtime;
                const off = c.u32leb() orelse return .runtime;
                const value = pop() orelse return .runtime;
                const base_addr: u32 = @truncate(pop() orelse return .runtime);
                const n: usize = switch (op) {
                    0x36, 0x3e => 4,
                    0x37 => 8,
                    0x3b, 0x3d => 2,
                    else => 1,
                };
                if (!store(base_addr, off, value, n)) return .runtime;
            },
            0x3f => { // memory.size
                if (c.byte() != 0 or !push(memory_len / PAGE)) return .runtime;
            },
            0x40 => { // memory.grow
                if (c.byte() != 0) return .runtime;
                const add: u32 = @truncate(pop() orelse return .runtime);
                const old = memory_len / PAGE;
                const wanted = @as(u64, old) + add;
                if (wanted * PAGE > memory_max) {
                    if (!push(0xffffffff)) return .limit;
                } else {
                    const next: usize = @intCast(wanted * PAGE);
                    @memset(memory[memory_len..next], 0);
                    memory_len = next;
                    if (!push(old)) return .limit;
                }
            },
            0x41 => if (!push(@as(u32, @bitCast(c.i32leb() orelse return .runtime)))) return .limit, // i32.const
            0x42 => if (!push(@bitCast(c.i64leb() orelse return .runtime))) return .limit, // i64.const
            0x45...0x5a, 0x67...0x8a, 0xc0...0xc4 => {
                const t = execNumber(op);
                if (t != .ok) return t;
            },
            0xa7 => { // i32.wrap_i64
                const x = pop() orelse return .runtime;
                if (!push(@as(u32, @truncate(x)))) return .limit;
            },
            0xac => { // i64.extend_i32_s
                const x: i32 = @bitCast(@as(u32, @truncate(pop() orelse return .runtime)));
                if (!push(@bitCast(@as(i64, x)))) return .limit;
            },
            0xad => if (!push(@as(u32, @truncate(pop() orelse return .runtime)))) return .limit, // i64.extend_i32_u
            0xfc => {
                const sub = c.u32leb() orelse return .runtime;
                switch (sub) {
                    8 => { // memory.init
                        const data = c.u32leb() orelse return .runtime;
                        if (data >= m.ndatas or c.u32leb() != 0) return .runtime;
                        const len: u32 = @truncate(pop() orelse return .runtime);
                        const src: u32 = @truncate(pop() orelse return .runtime);
                        const dst: u32 = @truncate(pop() orelse return .runtime);
                        const d = m.datas[data];
                        const at = addr(dst, 0, len) orelse return .runtime;
                        const source_len: u32 = if (data_dropped[data]) 0 else d.len;
                        if (@as(u64, src) + len > source_len or !chargeBytes(lim, len)) return if (lim.fuel == 0) .limit else .runtime;
                        @memcpy(memory[at..][0..len], d.data[src..][0..len]);
                    },
                    9 => { // data.drop
                        const data = c.u32leb() orelse return .runtime;
                        if (data >= m.ndatas) return .runtime;
                        data_dropped[data] = true;
                    },
                    10 => { // memory.copy
                        if (c.u32leb() != 0 or c.u32leb() != 0) return .runtime;
                        const len: u32 = @truncate(pop() orelse return .runtime);
                        const src: u32 = @truncate(pop() orelse return .runtime);
                        const dst: u32 = @truncate(pop() orelse return .runtime);
                        const from = addr(src, 0, len) orelse return .runtime;
                        const to = addr(dst, 0, len) orelse return .runtime;
                        if (!chargeBytes(lim, len)) return .limit;
                        @memmove(memory[to..][0..len], memory[from..][0..len]);
                    },
                    11 => { // memory.fill
                        if (c.u32leb() != 0) return .runtime;
                        const len: u32 = @truncate(pop() orelse return .runtime);
                        const byte: u8 = @truncate(pop() orelse return .runtime);
                        const dst: u32 = @truncate(pop() orelse return .runtime);
                        const at = addr(dst, 0, len) orelse return .runtime;
                        if (!chargeBytes(lim, len)) return .limit;
                        @memset(memory[at..][0..len], byte);
                    },
                    else => return .unsupported,
                }
            },
            else => return .unsupported,
        }
    }
    return .runtime;
}

fn entry(m: *const Mod) ?u16 {
    var i: u8 = 0;
    while (i < m.nexports) : (i += 1) if (m.exports[i].kind == 0 and eql(m.exports[i].name.bytes(), "_start")) return m.exports[i].idx;
    i = 0;
    while (i < m.nexports) : (i += 1) if (m.exports[i].kind == 0 and eql(m.exports[i].name.bytes(), "main")) return m.exports[i].idx;
    return null;
}

pub fn run(bytes: []const u8, limits_in: Limits, host: anytype, backing: []u8) Outcome {
    var m: Mod = undefined;
    var t = parseModule(bytes, &m);
    if (t != .ok) return .{ .trap = t };
    t = validateModule(&m);
    if (t != .ok) return .{ .trap = t };
    t = instantiate(&m, limits_in, backing);
    if (t != .ok) return .{ .trap = t };
    var lim = limits_in;
    var code: u8 = 0;
    sp = 0;
    if (m.has_start) {
        t = runFunc(&m, m.start, &lim, host, 0, &code);
        if (t != .ok) return .{ .trap = t, .code = code };
        sp = 0;
    }
    if (entry(&m)) |f| {
        const ft = &m.types[m.func_types[f]];
        if (ft.nparams != 0) return .{ .trap = .malformed };
        t = runFunc(&m, f, &lim, host, 0, &code);
        if (t == .ok and ft.nresults == 1) code = @truncate(pop() orelse return .{ .trap = .runtime });
        return .{ .trap = t, .code = code };
    }
    return if (m.has_start) .{ .trap = .ok } else .{ .trap = .runtime };
}

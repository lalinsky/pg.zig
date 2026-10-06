// Exposed within this library
const std = @import("std");

const build_config = @import("config");

pub const log = std.log.scoped(.pg);

pub const types = @import("types.zig");
pub const proto = @import("proto.zig");
pub const auth = @import("auth.zig");
pub const Conn = @import("conn.zig").Conn;
pub const Stmt = @import("stmt.zig").Stmt;
pub const DescribeCache = @import("describe_cache.zig").DescribeCache;
pub const Pool = @import("pool.zig").Pool;
pub const Stream = @import("stream.zig").Stream;
pub const sendTerminate = @import("stream.zig").sendTerminate;
pub const metrics = @import("metrics.zig");
pub const default_column_names = build_config.column_names;

const result = @import("result.zig");
pub const Row = result.Row;
pub const RowUnsafe = result.RowUnsafe;
pub const Result = result.Result;
pub const Iterator = result.Iterator;
pub const IteratorUnsafe = result.IteratorUnsafe;
pub const QueryRow = result.QueryRow;
pub const QueryRowUnsafe = result.QueryRowUnsafe;
pub const Mapper = result.Mapper;

const reader = @import("reader.zig");
pub const Reader = reader.Reader;
pub const Message = reader.Message;

pub const testing = @import("t.zig");

const root = @import("root");
const _assert = blk: {
    if (@hasDecl(root, "pg_assert")) {
        break :blk root.pg_assert;
    }
    switch (@import("builtin").mode) {
        .ReleaseFast, .ReleaseSmall => break :blk false,
        else => break :blk true,
    }
};

pub fn assert(ok: bool) void {
    if (comptime _assert) {
        std.debug.assert(ok);
    }
}

pub fn verifyDecodeType(comptime fail_mode: FailMode, comptime T: type, comptime expected_oids: []const i32, actual: i32) !void {
    if (comptime fail_mode == .safe) {
        if (isExpectedId(expected_oids, actual)) {
            return;
        }
        return error.InvalidType;
    }

    if (comptime _assert == false) {
        return;
    }

    if (isExpectedId(expected_oids, actual)) {
        return;
    }

    log.warn("PostgreSQL value of type {s} cannot be read into a " ++ @typeName(T) ++ ". " ++
        "pg.zig has strict type checking when reading value.", .{types.oidToString(actual)});
    unreachable;
}

fn isExpectedId(comptime expected_oids: []const i32, actual: i32) bool {
    inline for (expected_oids) |expected_oid| {
        if (expected_oid == actual) {
            return true;
        }
    }
    return false;
}

pub fn verifyNotNull(comptime fail_mode: FailMode, comptime T: type, is_null: bool) !void {
    if (comptime fail_mode == .safe) {
        if (is_null == false) {
            return;
        }
        return error.UnexpectedNull;
    }

    if (comptime _assert == false) {
        return;
    }

    if (is_null == false) {
        return;
    }

    log.warn("PostgreSQL null column cannot be read into non-optional type (" ++ @typeName(T) ++ "). " ++
        "pg.zig has strict type checking when reading value.", .{});
    unreachable;
}

pub fn verifyColumnName(comptime fail_mode: FailMode, name: []const u8, valid: bool) !void {
    if (comptime fail_mode == .safe) {
        if (valid) {
            return;
        }
        return error.UnknownColumnName;
    }

    if (comptime _assert == false) {
        return;
    }

    if (valid) {
        return;
    }

    log.warn("Unknown column name '{s}'", .{name});
    unreachable;
}

pub const ParsedOpts = struct {
    opts: Pool.Opts,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *ParsedOpts) void {
        self.arena.deinit();
    }
};

pub fn parseOpts(uri: std.Uri, allocator: std.mem.Allocator) !ParsedOpts {
    if (!std.mem.eql(u8, uri.scheme, "postgresql") and !std.mem.eql(u8, uri.scheme, "postgres")) {
        return error.InvalidUriScheme;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    var tls: Conn.Opts.TLS = .off;
    var tcp_user_timeout: ?u32 = null;
    var describe_cache: bool = false;
    var describe_cache_size: u16 = 512;
    if (uri.query) |qry| {
        const query_string = try qry.toRawMaybeAlloc(aa);
        var it = std.mem.splitScalar(u8, query_string, '&');
        while (it.next()) |param| {
            var it2 = std.mem.splitScalar(u8, param, '=');
            const key = it2.first();
            const val = it2.rest();
            if (std.mem.eql(u8, key, "tcp_user_timeout")) {
                tcp_user_timeout = try std.fmt.parseInt(u32, val, 10);
            } else if (std.mem.eql(u8, key, "describe_cache")) {
                if (std.mem.eql(u8, val, "true")) {
                    describe_cache = true;
                } else if (std.mem.eql(u8, val, "false") == false) {
                    return error.InvalidDescribeCacheValue;
                }
            } else if (std.mem.eql(u8, key, "describe_cache_size")) {
                describe_cache_size = try std.fmt.parseInt(u16, val, 10);
            } else if (std.mem.eql(u8, key, "sslmode")) {
                if (std.mem.eql(u8, val, "require")) {
                    tls = .require;
                } else if (std.mem.eql(u8, val, "verify-full")) {
                    tls = .{ .verify_full = null };
                } else if (std.mem.eql(u8, val, "disable") == false) {
                    return error.UnsupportedSSLModeValue;
                }
            } else {
                return error.UnsupportedConnectionParam;
            }
        }
    }

    const path = std.mem.trimStart(u8, try uri.path.toRawMaybeAlloc(aa), "/");
    const host = if (uri.host) |host| try host.toRawMaybeAlloc(aa) else null;
    const username = if (uri.user) |user| try user.toRawMaybeAlloc(aa) else "postgres";
    const password = if (uri.password) |password| try password.toRawMaybeAlloc(aa) else null;

    return .{ .arena = arena, .opts = .{
        .size = 0,
        .timeout = 0,
        .auth = .{
            .username = username,
            .password = password,
            .database = if (path.len == 0) null else path,
            .timeout = tcp_user_timeout orelse 10_000,
        },
        .connect = .{
            .tls = tls,
            .port = uri.port orelse null,
            .host = host,
            .describe_cache = describe_cache,
            .describe_cache_size = describe_cache_size,
        },
    } };
}

pub const Binary = struct {
    data: []const u8,
};

const TestCase = struct {
    uri: []const u8,
    expected_opts: Pool.Opts,
};

pub const FailMode = enum {
    safe,
    unsafe,
};

pub const TypeError = error{
    InvalidType,
    UnexpectedNull,
    UnknownColumnName,
};

const valid_tcs: [3]TestCase = .{
    .{ .uri = "postgresql:///", .expected_opts = .{ .size = 0, .auth = .{ .username = "postgres" }, .connect = .{}, .timeout = 0 } },
    .{ .uri = "postgresql://user:pass@somehost:1234/somedb?tcp_user_timeout=5678", .expected_opts = .{ .size = 0, .auth = .{
        .username = "user",
        .password = "pass",
        .database = "somedb",
        .timeout = 5678,
    }, .connect = .{
        .host = "somehost",
        .port = 1234,
    }, .timeout = 0 } },
    .{ .uri = "postgresql:///?describe_cache=true&describe_cache_size=64", .expected_opts = .{ .size = 0, .auth = .{ .username = "postgres" }, .connect = .{
        .describe_cache = true,
        .describe_cache_size = 64,
    }, .timeout = 0 } },
};

test "URI: parse valid" {
    const a = std.testing.allocator;
    for (valid_tcs) |tc| {
        var po = parseOpts(try std.Uri.parse(tc.uri), a) catch |e| {
            std.log.err("failed to parse URI {s}", .{tc.uri});
            return e;
        };
        defer po.deinit();
        try std.testing.expectEqualDeep(tc.expected_opts, po.opts);
    }
}

test "URI: invalid scheme" {
    try std.testing.expectError(error.InvalidUriScheme, parseOpts(try std.Uri.parse("foobar:///"), std.testing.allocator));
}

test "URI: invalid params" {
    try std.testing.expectError(error.UnsupportedConnectionParam, parseOpts(try std.Uri.parse("postgresql:///?bar=baz"), std.testing.allocator));
    try std.testing.expectError(error.InvalidDescribeCacheValue, parseOpts(try std.Uri.parse("postgresql:///?describe_cache=yes"), std.testing.allocator));
}

test "public API errors don't include ReadFailed or WriteFailed" {
    // std.Io.Reader/Writer only say that the reader/writer failed. The
    // caller doesn't own ours, so it can't ask them why; the concrete error
    // must be returned instead.
    const Listener = @import("listener.zig").Listener;
    const c: *Conn = undefined;
    const p: *Pool = undefined;
    const r: *Result = undefined;
    const l: *Listener = undefined;
    const qr: *QueryRow = undefined;
    const S = struct { a: i32 };
    const results = .{
        @TypeOf(Conn.open(undefined, undefined, .{})),
        @TypeOf(c.auth(.{})),
        @TypeOf(c.exec("", .{})),
        @TypeOf(c.query("", .{ 1, 1.5, "a", &S{ .a = 1 } })),
        @TypeOf(c.row("", .{1})),
        @TypeOf(c.prepare("")),
        @TypeOf(c.begin()),
        @TypeOf(c.rollback()),
        @TypeOf(r.next()),
        @TypeOf(r.drain()),
        @TypeOf(qr.deinit()),
        @TypeOf(Pool.init(undefined, undefined, .{})),
        @TypeOf(p.exec("", .{})),
        @TypeOf(p.query("", .{})),
        @TypeOf(Listener.open(undefined, undefined, .{})),
        @TypeOf(l.auth(.{})),
        @TypeOf(l.listen("", .{})),
        @TypeOf(l.stop()),
    };
    @setEvalBranchQuota(100_000);
    inline for (results) |R| {
        inline for (@typeInfo(@typeInfo(R).error_union.error_set).error_set.?) |e| {
            try testing.expectEqual(false, comptime std.mem.eql(u8, e.name, "ReadFailed"));
            try testing.expectEqual(false, comptime std.mem.eql(u8, e.name, "WriteFailed"));
        }
    }
}

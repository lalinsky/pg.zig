const std = @import("std");
const builtin = @import("builtin");
const lib = @import("lib.zig");

const tls = if (lib.has_tls) @import("tls") else struct {};

const posix = std.posix;

const Conn = lib.Conn;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const DEFAULT_HOST = "127.0.0.1";

// What the TLS connections made with the same options share: the
// certificates `verify_full` trusts. A pool loads them once for all of its
// connections, rather than on every connect.
pub const TlsContext = struct {
    // null for `require`, which checks no certificate
    trust: if (lib.has_tls) ?tls.TrustStore else void,

    pub fn init(io: Io, allocator: Allocator, config: Conn.Opts.TLS) !TlsContext {
        if (comptime lib.has_tls == false) {
            return error.TlsNotConfigured;
        }
        switch (config) {
            .off, .require => return .{ .trust = null },
            .verify_full => |path| {
                var trust = try tls.TrustStore.init();
                errdefer trust.deinit();
                if (path) |p| {
                    try trust.addPemFile(allocator, io, .cwd(), p);
                } else {
                    try trust.addSystemBundle(allocator, io);
                }
                return .{ .trust = trust };
            },
        }
    }

    pub fn deinit(self: *TlsContext) void {
        if (comptime lib.has_tls == false) {
            return;
        }
        if (self.trust) |*trust| {
            trust.deinit();
        }
    }
};

// Per-connection TLS state, heap-allocated so that it never moves: the
// tls.Connection points at the socket's reader and writer, and its own reader
// and writer point at it. The Conn's Stream and the Reader's copy of it share
// one.
const TlsState = struct {
    conn: tls.Connection,
    // the ciphertext side
    socket_reader: Io.net.Stream.Reader,
    socket_writer: Io.net.Stream.Writer,
    // the cleartext side, unbuffered: Stream.read and Stream.writeAll are
    // given whole buffers
    reader: tls.Connection.Reader,
    writer: tls.Connection.Writer,
    // backs socket_reader and socket_writer
    buf: []u8,
    allocator: Allocator,

    fn deinit(self: *TlsState) void {
        self.conn.deinit();
        const allocator = self.allocator;
        allocator.free(self.buf);
        allocator.destroy(self);
    }

    const ReadError = Optional(@FieldType(tls.Connection.Reader, "err")) || Optional(@FieldType(Io.net.Stream.Reader, "err"));
    const WriteError = Optional(@FieldType(tls.Connection.Writer, "err")) || Optional(@FieldType(Io.net.Stream.Writer, "err"));

    fn Optional(comptime T: type) type {
        return @typeInfo(T).optional.child;
    }

    // The error behind the reader's ReadFailed. A failure of the transport is
    // the socket's own error.
    fn readError(self: *const TlsState) ReadError {
        const err = self.reader.err orelse return error.ReadFailed;
        if (err == error.ReadFailed) {
            return self.socket_reader.err orelse error.ReadFailed;
        }
        return err;
    }

    fn writeError(self: *const TlsState) WriteError {
        const err = self.writer.err orelse return error.WriteFailed;
        if (err == error.WriteFailed) {
            return self.socket_writer.err orelse error.WriteFailed;
        }
        return err;
    }
};

pub const Stream = struct {
    io: Io,
    stream: Io.net.Stream,
    // null for a plaintext (tls = .off) connection
    tls: if (lib.has_tls) ?*TlsState else void,

    // `ctx` is shared by the connections of a pool. Without one, a connection
    // that wants TLS loads what it needs itself.
    pub fn connect(io: Io, allocator: Allocator, opts: Conn.Opts, ctx: ?*const TlsContext) !Stream {
        if (opts.tls != .off and comptime lib.has_tls == false) {
            return error.TlsNotConfigured;
        }

        const stream = try connectSocket(io, opts);
        errdefer stream.close(io);

        if (comptime lib.has_tls == false) {
            return .{ .io = io, .stream = stream, .tls = {} };
        }
        if (opts.tls == .off) {
            return .{ .io = io, .stream = stream, .tls = null };
        }

        var own_ctx: ?TlsContext = null;
        defer if (own_ctx) |*c| c.deinit();
        const tls_ctx = ctx orelse blk: {
            own_ctx = try TlsContext.init(io, allocator, opts.tls);
            break :blk &own_ctx.?;
        };

        // PostgreSQL TLS starts off as a plain connection which we upgrade
        try writeStream(stream, io, &.{ 0, 0, 0, 8, 4, 210, 22, 47 });
        var buf = [1]u8{0};
        _ = try readStream(stream, io, &buf);
        if (buf[0] != 'S') {
            return error.SSLNotSupportedByServer;
        }

        const state = try allocator.create(TlsState);
        errdefer allocator.destroy(state);
        state.allocator = allocator;
        state.buf = try allocator.alloc(u8, tls.input_buffer_len + tls.output_buffer_len);
        errdefer allocator.free(state.buf);
        state.socket_reader = stream.reader(io, state.buf[0..tls.input_buffer_len]);
        state.socket_writer = stream.writer(io, state.buf[tls.input_buffer_len..]);

        // An IP address is checked against the certificate's IP addresses,
        // and sent as no SNI.
        const host = opts.host orelse DEFAULT_HOST;
        state.conn = tls.client(&state.socket_reader.interface, &state.socket_writer.interface, .{
            .io = io,
            .gpa = allocator,
            .host = host,
            .root_ca = if (tls_ctx.trust) |*trust| trust else null,
            .insecure_skip_verify = tls_ctx.trust == null,
        }) catch |err| switch (err) {
            error.ReadFailed => return state.socket_reader.err orelse err,
            error.WriteFailed => return state.socket_writer.err orelse err,
            else => return err,
        };
        state.reader = state.conn.reader(&.{});
        state.writer = state.conn.writer(&.{});

        return .{ .io = io, .stream = stream, .tls = state };
    }

    pub fn close(self: *Stream) void {
        if (comptime lib.has_tls) {
            if (self.tls) |state| {
                // Best-effort close_notify, shielded from cancellation like the
                // Terminate message, so teardown can't be interrupted.
                const prev = self.io.swapCancelProtection(.blocked);
                defer _ = self.io.swapCancelProtection(prev);
                state.conn.close() catch {};
                state.deinit();
                self.tls = null;
            }
        }
        self.stream.close(self.io);
    }

    pub fn shutdown(self: *const Stream, how: Io.net.ShutdownHow) !void {
        return self.stream.shutdown(self.io, how);
    }

    pub fn writeAll(self: *Stream, data: []const u8) !void {
        if (comptime lib.has_tls) {
            if (self.tls) |state| {
                const w = &state.writer.interface;
                w.writeAll(data) catch return state.writeError();
                w.flush() catch return state.writeError();
                return;
            }
        }
        return writeStream(self.stream, self.io, data);
    }

    pub fn read(self: *Stream, buf: []u8) !usize {
        if (comptime lib.has_tls) {
            if (self.tls) |state| {
                var vecs: [1][]u8 = .{buf};
                return state.reader.interface.readVec(&vecs) catch |err| switch (err) {
                    error.EndOfStream => return error.EndOfStream,
                    error.ReadFailed => return state.readError(),
                };
            }
        }
        return readStream(self.stream, self.io, buf);
    }
};

fn connectSocket(io: Io, opts: Conn.Opts) !Io.net.Stream {
    const host = opts.host orelse DEFAULT_HOST;
    const is_unix = host.len > 0 and host[0] == '/';

    const stream = try blk: {
        if (is_unix) {
            if (comptime Io.net.has_unix_sockets == false or std.posix.AF == void) {
                return error.UnixPathNotSupported;
            }
            const addr: Io.net.UnixAddress = try .init(host);
            break :blk addr.connect(io);
        }
        const port = opts.port orelse 5432;
        const hostname: Io.net.HostName = try .init(host);
        break :blk hostname.connect(io, port, .{ .mode = .stream });
    };
    errdefer stream.close(io);

    if (is_unix == false) {
        try setKeepalive(stream.socket.handle, opts);
    }
    return stream;
}

const TCP = switch (builtin.os.tag) {
    // Zig doesn't expose these /shrug
    .freebsd, .dragonfly => struct {
        pub const KEEPIDLE = 256;
        pub const KEEPINTVL = 512;
        pub const KEEPCNT = 1024;
    },
    .netbsd => struct {
        pub const KEEPIDLE = 3;
        pub const KEEPINTVL = 5;
        pub const KEEPCNT = 6;
    },
    .illumos => struct {
        pub const KEEPIDLE = 0x22;
        pub const KEEPCNT = 0x23;
        pub const KEEPINTVL = 0x24;
    },
    else => if (posix.TCP == void) struct {} else posix.TCP,
};

fn setKeepalive(handle: posix.socket_t, opts: Conn.Opts) !void {
    if (opts.keepalive == false) {
        return;
    }
    const on: c_int = 1;
    try setsockopt(handle, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&on));

    const level = posix.IPPROTO.TCP;

    if (opts.keepalive_idle) |idle| {
        const optname: ?u32 = comptime if (@hasDecl(TCP, "KEEPIDLE"))
            TCP.KEEPIDLE
        else if (@hasDecl(TCP, "KEEPALIVE"))
            TCP.KEEPALIVE
        else
            null;
        if (optname) |name| {
            const v: c_int = @intCast(idle);
            setsockopt(handle, level, name, std.mem.asBytes(&v)) catch {};
        }
    }

    if (opts.keepalive_interval) |intvl| {
        if (comptime @hasDecl(TCP, "KEEPINTVL")) {
            const v: c_int = @intCast(intvl);
            setsockopt(handle, level, TCP.KEEPINTVL, std.mem.asBytes(&v)) catch {};
        }
    }

    if (opts.keepalive_count) |cnt| {
        if (comptime @hasDecl(TCP, "KEEPCNT")) {
            const v: c_int = @intCast(cnt);
            setsockopt(handle, level, TCP.KEEPCNT, std.mem.asBytes(&v)) catch {};
        }
    }
}

fn setsockopt(fd: posix.socket_t, level: i32, optname: u32, opt: []const u8) !void {
    if (@import("builtin").os.tag != .windows) {
        return posix.setsockopt(fd, level, optname, opt);
    }

    const SO = posix.SO;
    const SOL = posix.SOL;
    const timeval = posix.timeval;

    var ms_buf: u32 = 0;
    var opt_ptr: [*]const u8 = opt.ptr;
    var opt_len: i32 = @intCast(opt.len);
    if (level == SOL.SOCKET and (optname == SO.RCVTIMEO or optname == SO.SNDTIMEO) and opt.len == @sizeOf(timeval)) {
        const tv: *const timeval = @ptrCast(@alignCast(opt.ptr));
        const total_ms = @as(i64, tv.sec) * 1000 + @divTrunc(@as(i64, tv.usec), 1000);
        ms_buf = if (total_ms < 0) 0 else @intCast(@min(total_ms, std.math.maxInt(u32)));
        opt_ptr = @ptrCast(&ms_buf);
        opt_len = @sizeOf(u32);
    }

    const in: []const u8 = @ptrCast(&std.os.windows.AFD.SOCKOPT_INFO{
        .mode = .set,
        .level = level,
        .optname = optname,
        .optval = opt_ptr,
        .optlen = @intCast(opt_len),
    });

    var iosb: std.os.windows.IO_STATUS_BLOCK = undefined;
    switch (std.os.windows.ntdll.NtDeviceIoControlFile(
        fd,
        null, // event
        null, // APC routine
        null, // APC context
        &iosb,
        std.os.windows.IOCTL.AFD.SOCKOPT,
        if (in.len > 0) in.ptr else null,
        @intCast(in.len),
        null,
        0,
    )) {
        .SUCCESS => return,
        .CANCELLED => return error.Canceled,
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        else => |status| return std.os.windows.unexpectedStatus(status),
    }
}

fn readStream(stream: Io.net.Stream, io: Io, buf: []u8) !usize {
    var vecs: [1][]u8 = .{buf};
    var reader = stream.reader(io, &.{});
    const r = &reader.interface;
    return r.readVec(&vecs) catch |err| switch (err) {
        error.ReadFailed => return reader.err orelse err,
        else => return err,
    };
}

fn writeStream(stream: Io.net.Stream, io: Io, data: []const u8) !void {
    var buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &buf);
    const w = &writer.interface;
    w.writeAll(data) catch |err| switch (err) {
        error.WriteFailed => return writer.err orelse err,
    };
    w.flush() catch |err| switch (err) {
        error.WriteFailed => return writer.err orelse err,
    };
}

// Sends a best-effort Terminate ('X') message, shielded from cancellation so
// teardown can't be interrupted.
pub fn sendTerminate(stream: *Stream, io: Io) void {
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);
    stream.writeAll(&.{ 'X', 0, 0, 0, 4 }) catch {};
}

const windows = @import("windows.zig");

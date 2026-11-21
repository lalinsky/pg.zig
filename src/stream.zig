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

// A cheap handle over a connected socket; copies (the Conn's and its
// Reader's) share one heap-allocated State. The State must never move: the
// std.Io interfaces handed out by reader() and writer() live in it, and under
// TLS, the tls.Connection points at the socket's reader and writer in it.
pub const Stream = struct {
    io: Io,
    state: *State,

    // ztls's ReadFailed and WriteFailed only say that its transport, our
    // socket, failed; getReadError and getWriteError return the socket's
    // error instead, so they aren't part of these sets.
    pub const ReadError = Io.net.Stream.Reader.Error || if (lib.has_tls) ErrorSetWithout(OptionalChild(@FieldType(tls.Connection.Reader, "err")), &.{error.ReadFailed}) else error{};
    pub const WriteError = Io.net.Stream.Writer.Error || if (lib.has_tls) ErrorSetWithout(OptionalChild(@FieldType(tls.Connection.Writer, "err")), &.{error.WriteFailed}) else error{};

    const State = struct {
        allocator: Allocator,
        stream: Io.net.Stream,
        // The socket's reader and writer. On a plaintext connection, these are
        // what reader() and writer() hand out. Under TLS, they carry ciphertext.
        socket_reader: Io.net.Stream.Reader,
        socket_writer: Io.net.Stream.Writer,
        // The message buffer: backs socket_reader on a plaintext connection,
        // and the TLS reader otherwise.
        read_buf: []u8,
        tls: if (lib.has_tls) ?Tls else void,

        const Tls = struct {
            conn: tls.Connection,
            // the cleartext side: what reader() and writer() hand out
            reader: tls.Connection.Reader,
            writer: tls.Connection.Writer,
            // record-sized ciphertext buffers, swapped into socket_reader and
            // socket_writer
            buf: []u8,
        };

        fn deinit(self: *State) void {
            const allocator = self.allocator;
            if (comptime lib.has_tls) {
                if (self.tls) |*t| {
                    t.conn.deinit();
                    allocator.free(t.buf);
                }
            }
            allocator.free(self.read_buf);
            allocator.destroy(self);
        }
    };

    // `ctx` is shared by the connections of a pool. Without one, a connection
    // that wants TLS loads what it needs itself.
    pub fn connect(io: Io, allocator: Allocator, opts: Conn.Opts, ctx: ?*const TlsContext) !Stream {
        if (opts.tls != .off and comptime lib.has_tls == false) {
            return error.TlsNotConfigured;
        }

        const socket = try connectSocket(io, opts);
        errdefer socket.close(io);

        const state = try allocator.create(State);
        state.* = .{
            .allocator = allocator,
            .stream = socket,
            .socket_reader = undefined,
            .socket_writer = undefined,
            .read_buf = &.{},
            .tls = if (comptime lib.has_tls) null else {},
        };
        errdefer state.deinit();

        // a std.Io.Reader needs room for at least a message's 5 byte header
        state.read_buf = try allocator.alloc(u8, @max(opts.read_buffer orelse 8192, 128));
        state.socket_reader = socket.reader(io, state.read_buf);
        // Every write is a complete batch of messages, so the socket writer
        // needs no buffer of its own.
        state.socket_writer = socket.writer(io, &.{});

        const self: Stream = .{ .io = io, .state = state };
        if (comptime lib.has_tls) {
            if (opts.tls != .off) {
                try self.startTls(allocator, opts, ctx);
            }
        }
        return self;
    }

    fn startTls(self: Stream, allocator: Allocator, opts: Conn.Opts, ctx: ?*const TlsContext) !void {
        const io = self.io;
        const state = self.state;

        var own_ctx: ?TlsContext = null;
        defer if (own_ctx) |*c| c.deinit();
        const tls_ctx = ctx orelse blk: {
            own_ctx = try TlsContext.init(io, allocator, opts.tls);
            break :blk &own_ctx.?;
        };

        // PostgreSQL TLS starts off as a plain connection which we upgrade:
        // send the SSLRequest and require an 'S' (SSL supported) reply.
        const w = &state.socket_writer.interface;
        w.writeAll(&.{ 0, 0, 0, 8, 4, 210, 22, 47 }) catch return self.getWriteError();
        w.flush() catch return self.getWriteError();
        const r = &state.socket_reader.interface;
        const reply = r.takeByte() catch |err| return switch (err) {
            error.EndOfStream => error.Closed,
            error.ReadFailed => self.getReadError(),
        };
        if (reply != 'S') {
            return error.SSLNotSupportedByServer;
        }

        // A conforming server sends nothing after the 'S' until it has our
        // ClientHello, so anything already buffered was injected by a
        // man-in-the-middle, and must not be read as if it came over TLS
        // (CVE-2021-23214 in libpq).
        if (r.bufferedLen() != 0) {
            return error.UnexpectedDataAfterSSLResponse;
        }

        // once assigned, the caller's errdefer (State.deinit) owns the buffer
        const buf = try allocator.alloc(u8, tls.input_buffer_len + tls.output_buffer_len);
        state.tls = .{ .conn = undefined, .reader = undefined, .writer = undefined, .buf = buf };
        const t = &state.tls.?;

        // The socket side now carries ciphertext and needs room for a whole
        // record, so it gets the TLS buffers; the message buffer moves to the
        // cleartext side below.
        r.buffer = buf[0..tls.input_buffer_len];
        r.seek = 0;
        r.end = 0;
        w.buffer = buf[tls.input_buffer_len..];

        // An IP address is checked against the certificate's IP addresses,
        // and sent as no SNI.
        const host = opts.host orelse DEFAULT_HOST;
        t.conn = tls.client(r, w, .{
            .io = io,
            .gpa = allocator,
            .host = host,
            .root_ca = if (tls_ctx.trust) |*trust| trust else null,
            .insecure_skip_verify = tls_ctx.trust == null,
        }) catch |err| {
            // State.deinit would deinit the connection that wasn't made
            state.tls = null;
            allocator.free(buf);
            return switch (err) {
                // ztls reports its transport failing as ReadFailed and
                // WriteFailed; return the socket's error (e.g. Canceled), as a
                // plaintext connection would
                error.ReadFailed => state.socket_reader.err orelse error.Unexpected,
                error.WriteFailed => state.socket_writer.err orelse error.Unexpected,
                error.EndOfStream => error.Closed,
                else => |e| e,
            };
        };
        t.reader = t.conn.reader(state.read_buf);
        t.writer = t.conn.writer(&.{});
    }

    pub fn close(self: *Stream) void {
        const state = self.state;
        if (comptime lib.has_tls) {
            if (state.tls) |*t| {
                // Best-effort close_notify, shielded from cancellation like the
                // Terminate message, so teardown can't be interrupted.
                const prev = self.io.swapCancelProtection(.blocked);
                defer _ = self.io.swapCancelProtection(prev);
                t.conn.close() catch {};
            }
        }
        state.stream.close(self.io);
        state.deinit();
    }

    pub fn shutdown(self: *const Stream, how: Io.net.ShutdownHow) !void {
        return self.state.stream.shutdown(self.io, how);
    }

    pub fn reader(self: Stream) *Io.Reader {
        const state = self.state;
        if (comptime lib.has_tls) {
            if (state.tls) |*t| return &t.reader.interface;
        }
        return &state.socket_reader.interface;
    }

    pub fn writer(self: Stream) *Io.Writer {
        const state = self.state;
        if (comptime lib.has_tls) {
            if (state.tls) |*t| return &t.writer.interface;
        }
        return &state.socket_writer.interface;
    }

    pub fn writeAll(self: *Stream, data: []const u8) WriteError!void {
        const w = self.writer();
        w.writeAll(data) catch return self.getWriteError();
        w.flush() catch return self.getWriteError();
    }

    // std.Io.Reader and Writer report every failure as ReadFailed or
    // WriteFailed, and leave the real error on the implementation; these
    // return it, like std.http.Client.Connection.getReadError. Only
    // meaningful right after such a failure. Under TLS, a ReadFailed or
    // WriteFailed from ztls means that its transport, our socket, failed.
    pub fn getReadError(self: Stream) ReadError {
        const state = self.state;
        if (comptime lib.has_tls) {
            if (state.tls) |*t| {
                if (t.reader.err) |err| switch (err) {
                    error.ReadFailed => {},
                    else => |e| return e,
                };
            }
        }
        return state.socket_reader.err orelse error.Unexpected;
    }

    pub fn getWriteError(self: Stream) WriteError {
        const state = self.state;
        if (comptime lib.has_tls) {
            if (state.tls) |*t| {
                if (t.writer.err) |err| switch (err) {
                    error.WriteFailed => {},
                    else => |e| return e,
                };
            }
        }
        return state.socket_writer.err orelse error.Unexpected;
    }
};

fn OptionalChild(comptime T: type) type {
    return @typeInfo(T).optional.child;
}

// E without the errors in `excluded`
fn ErrorSetWithout(comptime E: type, comptime excluded: []const anyerror) type {
    var result = error{};
    outer: for (@typeInfo(E).error_set.error_names.?) |name| {
        for (excluded) |x| {
            if (std.mem.eql(u8, name, @errorName(x))) continue :outer;
        }
        result = result || @TypeOf(@field(anyerror, name));
    }
    return result;
}

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

// Sends a best-effort Terminate ('X') message, shielded from cancellation so
// teardown can't be interrupted.
pub fn sendTerminate(stream: *Stream, io: Io) void {
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);
    stream.writeAll(&.{ 'X', 0, 0, 0, 4 }) catch {};
}

const windows = @import("windows.zig");

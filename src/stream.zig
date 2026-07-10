const std = @import("std");
const builtin = @import("builtin");
const lib = @import("lib.zig");

const openssl = lib.openssl;

const posix = std.posix;

const Conn = lib.Conn;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const DEFAULT_HOST = "127.0.0.1";

pub const Stream = if (lib.has_openssl) TLSStream else PlainStream;

// TLS runs over memory BIOs: OpenSSL never touches the socket. All network
// I/O goes through the Io interface (readStream/writeStream), so waiting
// suspends the coroutine instead of blocking the event-loop thread.
const TLSStream = struct {
    valid: bool,
    ssl: ?*openssl.SSL,
    stream: Io.net.Stream,
    io: Io,

    pub fn connect(io: Io, allocator: Allocator, opts: Conn.Opts, ctx_: ?*openssl.SSL_CTX) !Stream {
        const plain = try PlainStream.connect(io, allocator, opts, null);
        errdefer plain.close();

        const stream = plain.stream;

        var ssl: ?*openssl.SSL = null;
        if (ctx_) |ctx| {
            // PostgreSQL TLS starts off as a plain connection which we upgrade
            try writeStream(stream, io, &.{ 0, 0, 0, 8, 4, 210, 22, 47 });
            var buf = [1]u8{0};
            _ = try readStream(stream, io, &buf);
            if (buf[0] != 'S') {
                return error.SSLNotSupportedByServer;
            }

            ssl = openssl.SSL_new(ctx) orelse return error.SSLNewFailed;
            errdefer openssl.SSL_free(ssl);

            const rbio = openssl.BIO_new(openssl.BIO_s_mem()) orelse return error.SSLNewFailed;
            const wbio = openssl.BIO_new(openssl.BIO_s_mem()) orelse {
                _ = openssl.BIO_free(rbio);
                return error.SSLNewFailed;
            };
            // ownership of both BIOs transfers to ssl; SSL_free frees them
            openssl.SSL_set_bio(ssl, rbio, wbio);

            if (opts.host) |host| {
                if (isHostName(host)) {
                    // don't send this for an ip address
                    var owned = false;
                    const h = opts._hostz orelse blk: {
                        owned = true;
                        break :blk try allocator.dupeZ(u8, host);
                    };

                    defer if (owned) {
                        allocator.free(h);
                    };

                    if (openssl.SSL_set_tlsext_host_name(ssl, h.ptr) != 1) {
                        return error.SSLHostNameFailed;
                    }

                    switch (opts.tls) {
                        // SNI alone doesn't bind the certificate to the hostname;
                        // without this, any CA-valid cert passes verify_full.
                        .verify_full => if (openssl.SSL_set1_host(ssl, h.ptr) != 1) {
                            return error.SSLHostNameFailed;
                        },
                        else => {},
                    }
                }
                switch (opts.tls) {
                    .verify_full => openssl.SSL_set_verify(ssl, openssl.SSL_VERIFY_PEER, null),
                    else => {},
                }
            }

            while (true) {
                openssl.ERR_clear_error();
                const ret = openssl.SSL_connect(ssl);
                // classify before flushBio touches OpenSSL again (SSL_get_error contract)
                const err = if (ret == 1) 0 else openssl.SSL_get_error(ssl, ret);
                flushBio(wbio, stream, io) catch return error.SSLConnectFailed;
                if (ret == 1) break;
                switch (err) {
                    openssl.SSL_ERROR_WANT_READ => fillBio(rbio, stream, io) catch return error.SSLConnectFailed,
                    else => {
                        const verification_code = openssl.SSL_get_verify_result(ssl);
                        if (comptime lib._stderr_tls) {
                            lib.printSSLError();
                        }
                        if (verification_code != openssl.X509_V_OK) {
                            if (comptime lib._stderr_tls) {
                                std.debug.print("ssl verification error: {s}\n", .{openssl.X509_verify_cert_error_string(verification_code)});
                            }
                            return error.SSLCertificationVerificationError;
                        }
                        return error.SSLConnectFailed;
                    },
                }
            }
        }

        return .{
            .ssl = ssl,
            .valid = true,
            .stream = stream,
            .io = io,
        };
    }

    pub fn close(self: *Stream) void {
        if (self.ssl) |ssl| {
            if (self.valid) {
                _ = openssl.SSL_shutdown(ssl);
                flushBio(openssl.SSL_get_wbio(ssl).?, self.stream, self.io) catch {}; // best-effort close_notify
                self.valid = false;
            }
            openssl.SSL_free(ssl);
        }
        self.stream.close(self.io);
    }

    pub fn shutdown(self: *const Stream, how: ShutdownHow) !void {
        return sockShutdown(self.stream.socket.handle, how);
    }

    pub fn writeAll(self: *Stream, data: []const u8) !void {
        if (self.ssl) |ssl| {
            return sslWrite(ssl, self.stream, self.io, data) catch {
                self.valid = false;
                return error.SSLWriteFailed;
            };
        }
        return writeStream(self.stream, self.io, data);
    }

    pub fn read(self: *Stream, buf: []u8) !usize {
        if (self.ssl) |ssl| {
            return sslRead(ssl, self.stream, self.io, buf) catch {
                self.valid = false;
                return error.SSLReadFailed;
            };
        }

        return readStream(self.stream, self.io, buf);
    }
};

fn sslWrite(ssl: *openssl.SSL, stream: Io.net.Stream, io: Io, data: []const u8) !void {
    while (true) {
        openssl.ERR_clear_error();
        const result = openssl.SSL_write(ssl, data.ptr, @intCast(data.len));
        // classify before flushBio touches OpenSSL again (SSL_get_error contract)
        const err = if (result > 0) 0 else openssl.SSL_get_error(ssl, result);
        try flushBio(openssl.SSL_get_wbio(ssl).?, stream, io);
        if (result > 0) {
            // no partial-write mode + unbounded memory BIO: result > 0 means all of data
            return;
        }
        switch (err) {
            // WANT_READ mid-write: TLS 1.3 key update / renegotiation
            openssl.SSL_ERROR_WANT_READ => try fillBio(openssl.SSL_get_rbio(ssl).?, stream, io),
            else => return error.SSLWriteFailed,
        }
    }
}

fn sslRead(ssl: *openssl.SSL, stream: Io.net.Stream, io: Io, buf: []u8) !usize {
    while (true) {
        openssl.ERR_clear_error();
        var read_len: usize = undefined;
        if (openssl.SSL_read_ex(ssl, buf.ptr, buf.len, &read_len) > 0) {
            return read_len;
        }
        switch (openssl.SSL_get_error(ssl, 0)) {
            openssl.SSL_ERROR_WANT_READ => {
                // flush first: SSL may need to send (e.g. key update ack) before it can read
                try flushBio(openssl.SSL_get_wbio(ssl).?, stream, io);
                try fillBio(openssl.SSL_get_rbio(ssl).?, stream, io);
            },
            else => return error.SSLReadFailed,
        }
    }
}

// drain everything OpenSSL queued in the write BIO out to the socket
fn flushBio(wbio: *openssl.BIO, stream: Io.net.Stream, io: Io) !void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = openssl.BIO_read(wbio, &buf, buf.len);
        if (n <= 0) return; // memory BIO: <= 0 just means empty
        try writeStream(stream, io, buf[0..@intCast(n)]);
    }
}

// read from the socket (suspends the coroutine) and feed OpenSSL's read BIO
fn fillBio(rbio: *openssl.BIO, stream: Io.net.Stream, io: Io) !void {
    var buf: [4096]u8 = undefined;
    const n = try readStream(stream, io, &buf);
    if (n == 0) {
        // readVec surfaces EOF as error.EndOfStream, so this shouldn't happen;
        // guard anyway — feeding 0 bytes to the BIO would livelock the caller
        return error.SSLReadFailed;
    }
    if (openssl.BIO_write(rbio, &buf, @intCast(n)) != n) {
        return error.SSLReadFailed;
    }
}

const PlainStream = struct {
    io: Io,
    stream: Io.net.Stream,

    pub fn connect(io: Io, _: Allocator, opts: Conn.Opts, _: anytype) !PlainStream {
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

        return .{
            .io = io,
            .stream = stream,
        };
    }

    pub fn close(self: *const PlainStream) void {
        self.stream.close(self.io);
    }

    pub fn shutdown(self: *const PlainStream, how: ShutdownHow) !void {
        const sock = self.stream.socket.handle;
        return sockShutdown(sock, how);
    }

    pub fn writeAll(self: *const PlainStream, data: []const u8) !void {
        return writeStream(self.stream, self.io, data);
    }

    pub fn read(self: *const PlainStream, buf: []u8) !usize {
        return readStream(self.stream, self.io, buf);
    }
};

fn setKeepalive(handle: posix.socket_t, opts: Conn.Opts) !void {
    if (opts.keepalive == false) {
        return;
    }
    const on: c_int = 1;
    try setsockopt(handle, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&on));

    const TCP = posix.TCP;
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

const ShutdownHow = enum { recv, send, both };
fn sockShutdown(sock: posix.socket_t, how: ShutdownHow) !void {
    if (comptime @import("builtin").os.tag == .windows) {
        const in: []const u8 = @ptrCast(&std.os.windows.AFD.PARTIAL_DISCONNECT_INFO{
            .DisconnectMode = switch (how) {
                .recv => .{ .RECEIVE = true },
                .send => .{ .SEND = true },
                .both => .{ .RECEIVE = true, .SEND = true },
            },
            .Timeout = -1,
        });

        var iosb: std.os.windows.IO_STATUS_BLOCK = undefined;
        switch (std.os.windows.ntdll.NtDeviceIoControlFile(
            sock,
            null, // event
            null, // APC routine
            null, // APC context
            &iosb,
            std.os.windows.IOCTL.AFD.PARTIAL_DISCONNECT,
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
    } else {
        const rc = posix.system.shutdown(sock, switch (how) {
            .recv => posix.system.SHUT.RD,
            .send => posix.system.SHUT.WR,
            .both => posix.system.SHUT.RDWR,
        });
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .BADF => unreachable,
            .INVAL => unreachable,
            .NOTCONN => return error.SocketNotConnected,
            .NOTSOCK => unreachable,
            .NOBUFS => return error.SystemResources,
            else => return error.Unexpected,
        }
    }
}
fn readStream(stream: Io.net.Stream, io: Io, buf: []u8) !usize {
    var vecs: [1][]u8 = .{buf};
    var reader = stream.reader(io, &.{});
    const r = &reader.interface;
    return try r.readVec(&vecs);
}

fn writeStream(stream: Io.net.Stream, io: Io, data: []const u8) !void {
    var buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &buf);
    const w = &writer.interface;
    try w.writeAll(data);
    try w.flush();
}

fn isHostName(host: []const u8) bool {
    if (std.mem.findScalar(u8, host, ':') != null) {
        // IPv6
        return false;
    }
    return std.mem.findNone(u8, host, "0123456789.") != null;
}

const windows = @import("windows.zig");

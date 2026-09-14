const std = @import("std");
const tls = @import("tls.zig");
const Socket = @import("../net/socket.zig").Socket;
const IoContext = @import("../io/context.zig").IoContext;

test {
    _ = @import("server_io_test.zig");
}

/// Borrowed only during acceptServerWithIo, not retained by the Connection.
/// Each budget covers one complete handshake-message I/O operation, including
/// all TLS records and partial socket progress. CCS has its own operation.
pub const HandshakeIoOptions = struct {
    context: *const IoContext,
    /// Null adds no deadline; zero expires before the operation accesses I/O.
    read_timeout_ms: ?u64 = null,
    write_timeout_ms: ?u64 = null,
};

pub const Tls13Kex = enum {
    x25519,
    x25519mlkem768,
};

pub fn acceptServer(
    allocator: std.mem.Allocator,
    socket: *Socket,
    protocols: []const []const u8,
    config: ?tls.ServerTLSConfig,
) !tls.Connection {
    return @import("server_runtime.zig").accept(allocator, socket, protocols, config);
}

/// Handshake-only cancellation/deadlines. Use Connection's existing
/// readWithContext/writeWithContext/writeAllWithContext after this returns.
pub fn acceptServerWithIo(
    allocator: std.mem.Allocator,
    socket: *Socket,
    protocols: []const []const u8,
    config: ?tls.ServerTLSConfig,
    options: HandshakeIoOptions,
) !tls.Connection {
    return @import("server_runtime.zig").acceptWithIo(allocator, socket, protocols, config, options);
}

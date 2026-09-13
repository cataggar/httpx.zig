const std = @import("std");
const tls = @import("tls.zig");
const Socket = @import("../net/socket.zig").Socket;

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

const std = @import("std");
const mem = std.mem;

const Socket = @import("../net/socket.zig").Socket;
const types = @import("../core/types.zig");
const address_mod = @import("../net/address.zig");
const compat = @import("../net/compat.zig");
const IoContext = @import("../io/context.zig").IoContext;

fn readNoEof(socket: *Socket, out: []u8, context: ?*const IoContext) !void {
    var read: usize = 0;
    while (read < out.len) {
        const n = if (context) |io_context|
            try socket.recvWithContext(out[read..], io_context)
        else
            try socket.recv(out[read..]);
        if (n == 0) return error.UnexpectedEof;
        read += n;
    }
}

fn writeAll(socket: *Socket, data: []const u8, context: ?*const IoContext) !void {
    if (context) |io_context| return socket.sendAllWithContext(data, io_context);
    return socket.sendAll(data);
}

fn writeSocksPort(socket: *Socket, port: u16, context: ?*const IoContext) !void {
    var port_bytes: [2]u8 = undefined;
    mem.writeInt(u16, &port_bytes, port, .big);
    try writeAll(socket, &port_bytes, context);
}

fn connectSocks5hTunnel(
    socket: *Socket,
    target_host: []const u8,
    target_port: u16,
    proxy: types.Proxy,
    context: ?*const IoContext,
) !void {
    var greeting: [4]u8 = undefined;
    greeting[0] = 0x05;
    if (proxy.username) |_| {
        greeting[1] = 0x02;
        greeting[2] = 0x00;
        greeting[3] = 0x02;
        try writeAll(socket, greeting[0..4], context);
    } else {
        greeting[1] = 0x01;
        greeting[2] = 0x00;
        try writeAll(socket, greeting[0..3], context);
    }

    var method_reply: [2]u8 = undefined;
    try readNoEof(socket, &method_reply, context);
    if (method_reply[0] != 0x05 or method_reply[1] == 0xff) return error.ProxyConnectionFailed;

    if (method_reply[1] == 0x02) {
        const username = proxy.username orelse return error.ProxyConnectionFailed;
        const password = proxy.password orelse "";
        if (username.len > 255 or password.len > 255) return error.ProxyConnectionFailed;

        var auth_header: [2]u8 = .{ 0x01, @intCast(username.len) };
        try writeAll(socket, &auth_header, context);
        try writeAll(socket, username, context);

        var password_len: [1]u8 = .{@intCast(password.len)};
        try writeAll(socket, &password_len, context);
        try writeAll(socket, password, context);

        var auth_reply: [2]u8 = undefined;
        try readNoEof(socket, &auth_reply, context);
        if (auth_reply[0] != 0x01 or auth_reply[1] != 0x00) return error.ProxyConnectionFailed;
    } else if (method_reply[1] != 0x00) {
        return error.ProxyConnectionFailed;
    }

    if (address_mod.isIpAddress(target_host)) {
        const ip = try compat.Address.parseIp(target_host, target_port);
        const ip_addr = ip.toIpAddress();
        switch (ip_addr) {
            .ip4 => |ip4| {
                var header: [4]u8 = .{ 0x05, 0x01, 0x00, 0x01 };
                try writeAll(socket, &header, context);
                try writeAll(socket, &ip4.bytes, context);
            },
            .ip6 => |ip6| {
                var header: [4]u8 = .{ 0x05, 0x01, 0x00, 0x04 };
                try writeAll(socket, &header, context);
                try writeAll(socket, &ip6.bytes, context);
            },
        }
    } else {
        if (target_host.len > 255) return error.ProxyConnectionFailed;
        var header: [4]u8 = .{ 0x05, 0x01, 0x00, 0x03 };
        try writeAll(socket, &header, context);

        var host_len: [1]u8 = .{@intCast(target_host.len)};
        try writeAll(socket, &host_len, context);
        try writeAll(socket, target_host, context);
    }

    try writeSocksPort(socket, target_port, context);

    var reply_head: [4]u8 = undefined;
    try readNoEof(socket, &reply_head, context);
    if (reply_head[0] != 0x05 or reply_head[1] != 0x00) return error.ProxyConnectionFailed;

    const atyp = reply_head[3];
    switch (atyp) {
        0x01 => {
            var skip: [4]u8 = undefined;
            try readNoEof(socket, &skip, context);
        },
        0x03 => {
            var len: [1]u8 = undefined;
            try readNoEof(socket, &len, context);
            if (len[0] > 0) {
                var skip: [255]u8 = undefined;
                try readNoEof(socket, skip[0..len[0]], context);
            }
        },
        0x04 => {
            var skip: [16]u8 = undefined;
            try readNoEof(socket, &skip, context);
        },
        else => return error.ProxyConnectionFailed,
    }

    var skip_port: [2]u8 = undefined;
    try readNoEof(socket, &skip_port, context);
}

/// Establishes a SOCKS5h tunnel to the target host and port.
pub fn establishSocks5hTunnel(socket: *Socket, target_host: []const u8, target_port: u16, proxy: types.Proxy) !void {
    try connectSocks5hTunnel(socket, target_host, target_port, proxy, null);
}

pub fn establishSocks5hTunnelWithContext(
    socket: *Socket,
    target_host: []const u8,
    target_port: u16,
    proxy: types.Proxy,
    context: *const IoContext,
) !void {
    try connectSocks5hTunnel(socket, target_host, target_port, proxy, context);
}

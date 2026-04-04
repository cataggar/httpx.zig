//! Networking compatibility shims for Zig 0.16
//!
//! In Zig 0.16, `std.net` was removed and `posix.socket()` etc. were moved
//! to the new `std.Io` subsystem. This module provides thin wrappers around
//! the platform C library or Windows Winsock to keep the existing socket
//! abstraction compiling.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

/// A network address wrapping the raw POSIX `sockaddr` storage.
pub const Address = struct {
    any: posix.sockaddr,
    len: posix.socklen_t = @sizeOf(posix.sockaddr),

    pub fn getOsSockLen(self: Address) posix.socklen_t {
        return self.len;
    }

    pub fn getPort(self: Address) u16 {
        const family = self.any.family;
        if (family == posix.AF.INET) {
            const in4: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&self.any));
            return std.mem.bigToNative(u16, in4.port);
        }
        if (family == posix.AF.INET6) {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(&self.any));
            return std.mem.bigToNative(u16, in6.port);
        }
        return 0;
    }

    pub fn initIp4(bytes: [4]u8, port: u16) Address {
        var addr: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
        addr.family = posix.AF.INET;
        addr.port = std.mem.nativeToBig(u16, port);
        addr.addr = @bitCast(bytes);
        var result: Address = .{ .any = undefined, .len = @sizeOf(posix.sockaddr.in) };
        @as(*posix.sockaddr.in, @ptrCast(@alignCast(&result.any))).* = addr;
        return result;
    }

    pub fn initIp6(bytes: [16]u8, port: u16) Address {
        var addr: posix.sockaddr.in6 = std.mem.zeroes(posix.sockaddr.in6);
        addr.family = posix.AF.INET6;
        addr.port = std.mem.nativeToBig(u16, port);
        addr.addr = bytes;
        var result: Address = .{ .any = undefined, .len = @sizeOf(posix.sockaddr.in6) };
        @as(*posix.sockaddr.in6, @ptrCast(@alignCast(&result.any))).* = addr;
        return result;
    }

    pub fn parseIp(host: []const u8, port: u16) !Address {
        // Try IPv4 first.
        if (parseIp4Bytes(host)) |bytes| {
            return initIp4(bytes, port);
        }
        // TODO: IPv6 parsing.
        return error.InvalidAddress;
    }

    fn parseIp4Bytes(str: []const u8) ?[4]u8 {
        var result: [4]u8 = undefined;
        var octet_idx: usize = 0;
        var current_octet: u16 = 0;
        var digit_count: usize = 0;

        for (str) |c| {
            if (c == '.') {
                if (digit_count == 0 or octet_idx >= 3) return null;
                result[octet_idx] = @intCast(current_octet);
                octet_idx += 1;
                current_octet = 0;
                digit_count = 0;
            } else if (c >= '0' and c <= '9') {
                current_octet = current_octet * 10 + (c - '0');
                if (current_octet > 255) return null;
                digit_count += 1;
            } else {
                return null;
            }
        }

        if (digit_count == 0 or octet_idx != 3) return null;
        result[3] = @intCast(current_octet);
        return result;
    }
};

// ---------- Platform socket operations ----------

pub const SocketError = error{SocketCreateFailed};
pub const ConnectError = error{ConnectFailed};
pub const BindError = error{BindFailed};
pub const ListenError = error{ListenFailed};
pub const AcceptError = error{AcceptFailed};
pub const SendError = error{SendFailed};
pub const RecvError = error{RecvFailed};
pub const GetSockNameError = error{GetSockNameFailed};

const ws2 = if (is_windows) std.os.windows.ws2_32 else struct {};

/// Create a socket. On Windows this calls the ws2_32 `socket` function via
/// the C runtime (linked through `-lws2_32`). On POSIX it calls libc `socket`.
pub fn socketCreate(domain: u32, sock_type: u32, protocol: u32) SocketError!posix.socket_t {
    if (is_windows) {
        const rc = socket(@intCast(domain), @intCast(sock_type), @intCast(protocol));
        if (rc == INVALID_SOCKET_WIN) return SocketError.SocketCreateFailed;
        return rc;
    } else {
        const rc = std.c.socket(@intCast(domain), @intCast(sock_type), @intCast(protocol));
        if (rc < 0) return SocketError.SocketCreateFailed;
        return rc;
    }
}

pub fn socketClose(handle: posix.socket_t) void {
    if (is_windows) {
        _ = closesocket(handle);
    } else {
        _ = std.c.close(handle);
    }
}

pub fn socketConnect(handle: posix.socket_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) ConnectError!void {
    if (is_windows) {
        if (connect(handle, addr, @intCast(addrlen)) != 0)
            return ConnectError.ConnectFailed;
    } else {
        if (std.c.connect(handle, @ptrCast(addr), addrlen) != 0)
            return ConnectError.ConnectFailed;
    }
}

pub fn socketBind(handle: posix.socket_t, addr: *const posix.sockaddr, addrlen: posix.socklen_t) BindError!void {
    if (is_windows) {
        if (bind(handle, addr, @intCast(addrlen)) != 0)
            return BindError.BindFailed;
    } else {
        if (std.c.bind(handle, @ptrCast(addr), addrlen) != 0)
            return BindError.BindFailed;
    }
}

pub fn socketListen(handle: posix.socket_t, backlog: u31) ListenError!void {
    if (is_windows) {
        if (listen(handle, @intCast(backlog)) != 0)
            return ListenError.ListenFailed;
    } else {
        if (std.c.listen(handle, @intCast(backlog)) != 0)
            return ListenError.ListenFailed;
    }
}

pub fn socketAccept(handle: posix.socket_t, addr: *posix.sockaddr, addrlen: *posix.socklen_t) AcceptError!posix.socket_t {
    if (is_windows) {
        const rc = accept(handle, addr, @ptrCast(addrlen));
        if (rc == INVALID_SOCKET_WIN) return AcceptError.AcceptFailed;
        return rc;
    } else {
        const rc = std.c.accept(handle, @ptrCast(addr), addrlen);
        if (rc < 0) return AcceptError.AcceptFailed;
        return rc;
    }
}

pub fn socketSend(handle: posix.socket_t, data: []const u8) SendError!usize {
    if (is_windows) {
        const rc = send(handle, data.ptr, @intCast(data.len), 0);
        if (rc < 0) return SendError.SendFailed;
        return @intCast(rc);
    } else {
        const rc = std.c.send(handle, @ptrCast(data.ptr), data.len, 0);
        if (rc < 0) return SendError.SendFailed;
        return @intCast(rc);
    }
}

pub fn socketRecv(handle: posix.socket_t, buffer: []u8) RecvError!usize {
    if (is_windows) {
        const rc = recv(handle, buffer.ptr, @intCast(buffer.len), 0);
        if (rc < 0) return RecvError.RecvFailed;
        return @intCast(rc);
    } else {
        const rc = std.c.recv(handle, @ptrCast(buffer.ptr), buffer.len, 0);
        if (rc < 0) return RecvError.RecvFailed;
        return @intCast(rc);
    }
}

pub fn socketSendTo(handle: posix.socket_t, data: []const u8, addr: *const posix.sockaddr, addrlen: posix.socklen_t) SendError!usize {
    if (is_windows) {
        const rc = sendto(handle, data.ptr, @intCast(data.len), 0, addr, @intCast(addrlen));
        if (rc < 0) return SendError.SendFailed;
        return @intCast(rc);
    } else {
        const rc = std.c.sendto(handle, @ptrCast(data.ptr), data.len, 0, @ptrCast(addr), addrlen);
        if (rc < 0) return SendError.SendFailed;
        return @intCast(rc);
    }
}

pub fn socketRecvFrom(handle: posix.socket_t, buffer: []u8, addr: *posix.sockaddr, addrlen: *posix.socklen_t) RecvError!usize {
    if (is_windows) {
        const rc = recvfrom(handle, buffer.ptr, @intCast(buffer.len), 0, addr, @ptrCast(addrlen));
        if (rc < 0) return RecvError.RecvFailed;
        return @intCast(rc);
    } else {
        const rc = std.c.recvfrom(handle, @ptrCast(buffer.ptr), buffer.len, 0, @ptrCast(addr), addrlen);
        if (rc < 0) return RecvError.RecvFailed;
        return @intCast(rc);
    }
}

pub fn socketGetSockName(handle: posix.socket_t, addr: *posix.sockaddr, addrlen: *posix.socklen_t) GetSockNameError!void {
    if (is_windows) {
        if (getsockname(handle, addr, @ptrCast(addrlen)) != 0)
            return GetSockNameError.GetSockNameFailed;
    } else {
        if (std.c.getsockname(handle, @ptrCast(addr), addrlen) != 0)
            return GetSockNameError.GetSockNameFailed;
    }
}

// ---------- Windows Winsock extern declarations ----------
// The actual ws2_32.dll export names use lowercase C standard names.

const INVALID_SOCKET_WIN: posix.socket_t = if (is_windows) @ptrFromInt(~@as(usize, 0)) else undefined;

extern "ws2_32" fn socket(af: i32, sock_type: i32, protocol: i32) callconv(.winapi) posix.socket_t;
extern "ws2_32" fn closesocket(s: posix.socket_t) callconv(.winapi) i32;
extern "ws2_32" fn connect(s: posix.socket_t, name: *const posix.sockaddr, namelen: i32) callconv(.winapi) i32;
extern "ws2_32" fn bind(s: posix.socket_t, addr: *const posix.sockaddr, namelen: i32) callconv(.winapi) i32;
extern "ws2_32" fn listen(s: posix.socket_t, backlog: i32) callconv(.winapi) i32;
extern "ws2_32" fn accept(s: posix.socket_t, addr: *posix.sockaddr, addrlen: *i32) callconv(.winapi) posix.socket_t;
extern "ws2_32" fn send(s: posix.socket_t, buf: [*]const u8, len: i32, flags: i32) callconv(.winapi) i32;
extern "ws2_32" fn recv(s: posix.socket_t, buf: [*]u8, len: i32, flags: i32) callconv(.winapi) i32;
extern "ws2_32" fn sendto(s: posix.socket_t, buf: [*]const u8, len: i32, flags: i32, to: *const posix.sockaddr, tolen: i32) callconv(.winapi) i32;
extern "ws2_32" fn recvfrom(s: posix.socket_t, buf: [*]u8, len: i32, flags: i32, from: *posix.sockaddr, fromlen: *i32) callconv(.winapi) i32;
extern "ws2_32" fn getsockname(s: posix.socket_t, name: *posix.sockaddr, namelen: *i32) callconv(.winapi) i32;
extern "ws2_32" fn setsockopt(s: posix.socket_t, level: i32, optname: i32, optval: [*]const u8, optlen: i32) callconv(.winapi) i32;

pub const SetSockOptError = error{SetSockOptFailed};

pub const WsaInitError = error{WsaInitFailed};

pub fn wsaInit() WsaInitError!void {
    if (!is_windows) return;
    var wsa_data: WSAData = undefined;
    if (WSAStartup(0x0202, &wsa_data) != 0)
        return WsaInitError.WsaInitFailed;
}

const WSAData = if (is_windows) extern struct {
    wVersion: u16,
    wHighVersion: u16,
    iMaxSockets: u16,
    iMaxUdpDg: u16,
    lpVendorInfo: ?[*]u8,
    szDescription: [257]u8,
    szSystemStatus: [129]u8,
} else void;

extern "ws2_32" fn WSAStartup(wVersionRequested: u16, lpWSAData: *WSAData) callconv(.winapi) i32;

pub fn socketSetSockOpt(handle: posix.socket_t, level: i32, optname: u32, opt: []const u8) SetSockOptError!void {
    if (is_windows) {
        if (setsockopt(handle, level, @intCast(optname), opt.ptr, @intCast(opt.len)) != 0)
            return SetSockOptError.SetSockOptFailed;
    } else {
        if (std.c.setsockopt(handle, level, @intCast(optname), @ptrCast(opt.ptr), @intCast(opt.len)) != 0)
            return SetSockOptError.SetSockOptFailed;
    }
}


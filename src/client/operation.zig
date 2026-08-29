//! Public streaming client operation contract.
//!
//! `ClientOperation` has one owner. Except for `cancel`, methods must not be
//! called concurrently. `deinit` aborts an operation which has not already
//! reached a terminal state.

const std = @import("std");
const Headers = @import("../core/headers.zig").Headers;
const Status = @import("../core/status.zig").Status;
const types = @import("../core/types.zig");

pub const BodyMode = union(enum) {
    none,
    content_length: u64,
    chunked,
};

pub const RequestProgress = struct {
    mode: BodyMode,
    bytes: u64 = 0,

    pub fn validateWrite(self: *const RequestProgress, amount: usize) !u64 {
        if (amount == 0) return self.bytes;
        const next = std.math.add(u64, self.bytes, amount) catch
            return error.BodyLengthOverflow;
        switch (self.mode) {
            .none => return error.RequestBodyNotAllowed,
            .content_length => |length| if (next > length) return error.RequestBodyOverrun,
            .chunked => {},
        }
        return next;
    }

    pub fn commit(self: *RequestProgress, next: u64) void {
        self.bytes = next;
    }

    pub fn finish(self: *const RequestProgress) !void {
        switch (self.mode) {
            .content_length => |length| if (self.bytes != length) return error.RequestBodyUnderrun,
            else => {},
        }
    }
};

pub const ResponseLimit = union(enum) {
    inherit,
    unlimited,
    bytes: u64,
};

pub const BasicAuth = struct {
    username: []const u8,
    password: []const u8,
};

pub const OpenOptions = struct {
    headers: ?[]const [2][]const u8 = null,
    query_params: ?[]const [2][]const u8 = null,
    bearer_token: ?[]const u8 = null,
    basic_auth: ?BasicAuth = null,
    timeout_ms: ?u64 = null,
    connect_timeout_ms: ?u64 = null,
    read_timeout_ms: ?u64 = null,
    write_timeout_ms: ?u64 = null,
    /// Null uses `timeouts.tls_handshake_ms`, falling back to connect timeout.
    /// Explicit zero disables the TLS-handshake phase timeout.
    tls_handshake_ms: ?u64 = null,
    /// Null uses `timeouts.header_ms`, falling back to read timeout.
    /// Explicit zero disables the whole response-header phase timeout.
    header_ms: ?u64 = null,
    timeouts: ?types.Timeouts = null,
    cancel_token: ?*const types.CancellationToken = null,
    policy: types.RequestPolicyOverrides = .{},
    version: ?types.Version = null,
    proxy: ?types.Proxy = null,
    verify_ssl: ?bool = null,
    keep_alive: ?bool = null,
    unix_socket_path: ?[]const u8 = null,
    range_header: ?[]const u8 = null,
    api_key_header: ?[]const u8 = null,
    api_key_value: ?[]const u8 = null,
    expect_100_continue: bool = false,
    body_mode: BodyMode = .none,
    response_limit: ResponseLimit = .inherit,
};

pub const ResponseHead = struct {
    version: types.Version,
    status: Status,
    headers: *const Headers,
};

pub const ContinueResult = enum {
    send_body,
    final_response,
};

pub const FinishOptions = struct {
    drain_response: bool = true,
    /// Independent upper bound for draining. Null uses ClientConfig.
    drain_timeout_ms: ?u64 = null,
};

pub const VTable = struct {
    write: *const fn (*anyopaque, []const u8) anyerror!usize,
    wait_for_continue: *const fn (*anyopaque) anyerror!ContinueResult,
    finish_request: *const fn (*anyopaque, ?[]const [2][]const u8) anyerror!*const ResponseHead,
    read: *const fn (*anyopaque, []u8) anyerror!usize,
    trailers: *const fn (*const anyopaque) ?*const Headers,
    finish: *const fn (*anyopaque, FinishOptions) anyerror!void,
    abort: *const fn (*anyopaque) void,
    cancel: *const fn (*anyopaque) void,
    destroy: *const fn (*anyopaque) void,
};

pub const ClientOperation = struct {
    driver: ?*anyopaque,
    vtable: *const VTable,

    const Self = @This();

    fn context(self: *const Self) *anyopaque {
        return self.driver orelse @panic("httpx.ClientOperation used after deinit");
    }

    pub fn write(self: *Self, data: []const u8) !usize {
        return self.vtable.write(self.context(), data);
    }

    pub fn writeAll(self: *Self, data: []const u8) !void {
        var offset: usize = 0;
        while (offset < data.len) {
            const n = try self.write(data[offset..]);
            if (n == 0 or n > data.len - offset) return error.WriteFailed;
            offset += n;
        }
    }

    /// Streams bytes from a borrowed reader using fixed storage.
    pub fn writeFromReader(self: *Self, reader: anytype) !u64 {
        var buffer: [32 * 1024]u8 = undefined;
        var total: u64 = 0;
        while (true) {
            const ReaderType = switch (@typeInfo(@TypeOf(reader))) {
                .pointer => |pointer| pointer.child,
                else => @TypeOf(reader),
            };
            const n = if (@hasDecl(ReaderType, "readSliceShort"))
                try reader.readSliceShort(&buffer)
            else
                try reader.read(&buffer);
            if (n == 0) return total;
            try self.writeAll(buffer[0..n]);
            total = std.math.add(u64, total, n) catch return error.BodyLengthOverflow;
        }
    }

    /// Waits at the request-head boundary when `Expect: 100-continue` is set.
    pub fn waitForContinue(self: *Self) !ContinueResult {
        return self.vtable.wait_for_continue(self.context());
    }

    pub fn finishRequest(self: *Self, trailer_fields: ?[]const [2][]const u8) !*const ResponseHead {
        return self.vtable.finish_request(self.context(), trailer_fields);
    }

    pub fn read(self: *Self, buffer: []u8) !usize {
        return self.vtable.read(self.context(), buffer);
    }

    pub fn trailers(self: *const Self) ?*const Headers {
        const driver = self.driver orelse return null;
        return self.vtable.trailers(driver);
    }

    pub fn finish(self: *Self, options: FinishOptions) !void {
        return self.vtable.finish(self.context(), options);
    }

    pub fn abort(self: *Self) void {
        const driver = self.driver orelse return;
        self.vtable.abort(driver);
    }

    /// Thread-safe signal. Active I/O observes it in bounded readiness waits.
    pub fn cancel(self: *Self) void {
        const driver = self.driver orelse return;
        self.vtable.cancel(driver);
    }

    pub fn deinit(self: *Self) void {
        const driver = self.driver orelse return;
        self.vtable.destroy(driver);
        self.driver = null;
    }
};

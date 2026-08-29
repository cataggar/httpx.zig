const std = @import("std");
const Allocator = std.mem.Allocator;
const net = @import("compat.zig");
const address_mod = @import("address.zig");
const common = @import("../data/common.zig");
const socket_mod = @import("socket.zig");
const IoContext = @import("../io/context.zig").IoContext;
const Deadline = @import("../io/context.zig").Deadline;
const CancellationToken = @import("../core/types.zig").CancellationToken;

const posix = std.posix;

pub const AddressFamily = enum {
    any,
    ipv4_only,
    ipv6_only,
};

pub const AddressOrder = enum {
    system,
    ipv4_preferred,
    ipv6_preferred,
};

pub const DnsRecordType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    _,
};

pub const DnsRecordClass = enum(u16) {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255,
    _,
};

pub const DnsServer = struct {
    ip: []const u8,
    port: u16 = 53,
};

pub const DNSConfig = struct {
    positive_ttl_ms: i64 = 60_000,
    negative_ttl_ms: i64 = 5_000,
    max_cache_entries: u32 = 1024,
    address_family: AddressFamily = .any,
    address_order: AddressOrder = .system,
    cache_enabled: bool = true,
    dedup_enabled: bool = true,
    dns_servers: []const DnsServer = &.{
        .{ .ip = "8.8.8.8" },
        .{ .ip = "8.8.4.4" },
        .{ .ip = "1.1.1.1" },
    },
    udp_timeout_ms: u64 = 3000,
    tcp_timeout_ms: u64 = 5000,
};

pub const DNSResolution = struct {
    hostname: []const u8,
    addresses: []net.Address,
    failed: bool = false,
    allocator: Allocator,

    pub fn deinit(self: *DNSResolution) void {
        self.allocator.free(self.addresses);
        self.* = undefined;
    }

    pub fn ok(self: *const DNSResolution) bool {
        return !self.failed and self.addresses.len > 0;
    }
};

pub const DNSStats = struct {
    hits: u64 = 0,
    misses: u64 = 0,
    failures: u64 = 0,
    evictions: u64 = 0,
    negative_hits: u64 = 0,
    dedup_hits: u64 = 0,
    literal_hits: u64 = 0,
    total_lookups: u64 = 0,
    udp_queries: u64 = 0,
    tcp_queries: u64 = 0,

    pub fn hitRate(self: DNSStats) f64 {
        const total = self.hits + self.misses;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.hits)) / @as(f64, @floatFromInt(total));
    }
};

fn putU16(buf: []u8, val: u16) void {
    buf[0] = @intCast(val >> 8);
    buf[1] = @intCast(val & 0xFF);
}

fn putU32(buf: []u8, val: u32) void {
    buf[0] = @intCast(val >> 24);
    buf[1] = @intCast((val >> 16) & 0xFF);
    buf[2] = @intCast((val >> 8) & 0xFF);
    buf[3] = @intCast(val & 0xFF);
}

fn getU16(buf: []const u8) u16 {
    return (@as(u16, buf[0]) << 8) | @as(u16, buf[1]);
}

fn getU32(buf: []const u8) u32 {
    return (@as(u32, buf[0]) << 24) | (@as(u32, buf[1]) << 16) | (@as(u32, buf[2]) << 8) | @as(u32, buf[3]);
}

const DnsHeader = extern struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,

    const Self = @This();

    pub fn flags_Query(recursion_desired: bool) u16 {
        var f: u16 = 0;
        if (recursion_desired) f |= 1 << 8;
        return f;
    }

    pub fn isResponse(self: Self) bool {
        return (self.flags & 0x8000) != 0;
    }

    pub fn rcode(self: Self) u4 {
        return @intCast(self.flags & 0x000F);
    }

    pub fn isTruncated(self: Self) bool {
        return (self.flags & 0x0200) != 0;
    }

    pub fn isAuthoritative(self: Self) bool {
        return (self.flags & 0x0400) != 0;
    }
};

const DnsQuestion = struct {
    name: []const u8,
    qtype: DnsRecordType,
    qclass: DnsRecordClass,
};

const DnsRecord = struct {
    name: []const u8,
    record_type: DnsRecordType,
    record_class: DnsRecordClass,
    ttl: i32,
    rdata: []const u8,
};

const DnsMessage = struct {
    header: DnsHeader,
    questions: []DnsQuestion,
    answers: []DnsRecord,
    allocator: Allocator,

    pub fn deinit(self: *DnsMessage) void {
        for (self.questions) |q| {
            self.allocator.free(q.name);
        }
        self.allocator.free(self.questions);
        for (self.answers) |a| {
            self.allocator.free(a.name);
            self.allocator.free(a.rdata);
        }
        self.allocator.free(self.answers);
    }
};

fn encodeDnsName(name: []const u8, buf: []u8) !struct { len: usize } {
    var pos: usize = 0;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len > 63) return error.NameLabelTooLong;
        if (pos + 1 + label.len > buf.len) return error.NameTooLong;
        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos .. pos + label.len], label);
        pos += label.len;
    }
    if (pos < buf.len) {
        buf[pos] = 0;
        pos += 1;
    }
    return .{ .len = pos };
}

fn decodeDnsName(data: []const u8, offset: *usize, out_buf: []u8) !usize {
    var name_len: usize = 0;
    var jumped = false;
    var original_offset = offset.*;

    var pos = offset.*;
    var jump_count: u8 = 0;
    var terminated = false;

    while (pos < data.len) {
        const label_len = data[pos];

        if (label_len == 0) {
            pos += 1;
            if (!jumped) offset.* = pos;
            terminated = true;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= data.len) return error.InvalidDnsName;
            if (!jumped) original_offset = pos + 2;
            const ptr = @as(u16, label_len & 0x3F) << 8 | @as(u16, data[pos + 1]);
            if (ptr >= data.len) return error.InvalidDnsName;
            pos = ptr;
            jumped = true;
            jump_count += 1;
            if (jump_count > 64) return error.DnsNameLoop;
            continue;
        }

        if (label_len > 63) return error.InvalidLabelLength;
        pos += 1;
        if (pos + label_len > data.len) return error.NameTruncated;
        if (name_len > 0) {
            if (name_len + 1 >= out_buf.len) return error.NameTooLong;
            out_buf[name_len] = '.';
            name_len += 1;
        }
        if (name_len + label_len >= out_buf.len) return error.NameTooLong;
        @memcpy(out_buf[name_len .. name_len + label_len], data[pos .. pos + label_len]);
        name_len += label_len;
        pos += label_len;
    }

    if (!terminated or pos > data.len) return error.InvalidDnsName;
    offset.* = if (jumped) original_offset else pos;
    return name_len;
}

fn encodeQuestion(q: DnsQuestion, buf: []u8) !usize {
    const name_result = try encodeDnsName(q.name, buf);
    var pos = name_result.len;

    if (pos + 4 > buf.len) return error.BufferTooSmall;
    putU16(buf[pos..], @intFromEnum(q.qtype));
    putU16(buf[pos + 2 ..], @intFromEnum(q.qclass));
    pos += 4;

    return pos;
}

fn parseDnsMessage(data: []const u8, allocator: Allocator) !DnsMessage {
    if (data.len < 12) return error.DnsMessageTooShort;

    const header = DnsHeader{
        .id = getU16(data[0..2]),
        .flags = getU16(data[2..4]),
        .qdcount = getU16(data[4..6]),
        .ancount = getU16(data[6..8]),
        .nscount = getU16(data[8..10]),
        .arcount = getU16(data[10..12]),
    };
    if (header.qdcount > data.len / 5 or
        header.ancount > data.len / 11 or
        @as(u64, header.qdcount) + header.ancount + header.nscount + header.arcount >
            data.len / 5)
    {
        return error.DnsRecordCountInvalid;
    }

    var offset: usize = 12;
    var name_buf: [256]u8 = undefined;

    const questions = try allocator.alloc(DnsQuestion, header.qdcount);
    var questions_initialized: usize = 0;
    errdefer {
        for (questions[0..questions_initialized]) |q| allocator.free(q.name);
        allocator.free(questions);
    }

    for (questions) |*q| {
        const name_len = try decodeDnsName(data, &offset, &name_buf);
        if (offset > data.len or data.len - offset < 4) return error.DnsMessageTruncated;
        q.name = try allocator.dupe(u8, name_buf[0..name_len]);
        q.qtype = @enumFromInt(getU16(data[offset..]));
        q.qclass = @enumFromInt(getU16(data[offset + 2 ..]));
        offset += 4;
        questions_initialized += 1;
    }

    const answers = try allocator.alloc(DnsRecord, header.ancount);
    var answers_initialized: usize = 0;
    errdefer {
        for (answers[0..answers_initialized]) |a| {
            allocator.free(a.name);
            allocator.free(a.rdata);
        }
        allocator.free(answers);
    }

    for (answers) |*a| {
        const name_len = try decodeDnsName(data, &offset, &name_buf);
        if (offset > data.len or data.len - offset < 10) return error.DnsMessageTruncated;
        const record_type: DnsRecordType = @enumFromInt(getU16(data[offset..]));
        const record_class: DnsRecordClass = @enumFromInt(getU16(data[offset + 2 ..]));
        const ttl: i32 = @bitCast(getU32(data[offset + 4 ..]));
        const rdlength = getU16(data[offset + 8 ..]);
        offset += 10;

        if (offset > data.len or rdlength > data.len - offset) return error.DnsMessageTruncated;
        const owner_name = try allocator.dupe(u8, name_buf[0..name_len]);
        errdefer allocator.free(owner_name);
        const rdata = if (record_type == .CNAME) blk: {
            var cname_offset = offset;
            const cname_len = try decodeDnsName(data, &cname_offset, &name_buf);
            if (cname_offset != offset + rdlength) return error.InvalidDnsName;
            break :blk try allocator.dupe(u8, name_buf[0..cname_len]);
        } else try allocator.dupe(u8, data[offset .. offset + rdlength]);
        errdefer allocator.free(rdata);
        a.name = owner_name;
        a.record_type = record_type;
        a.record_class = record_class;
        a.ttl = ttl;
        a.rdata = rdata;
        offset += rdlength;
        answers_initialized += 1;
    }

    return DnsMessage{
        .header = header,
        .questions = questions,
        .answers = answers,
        .allocator = allocator,
    };
}

fn validateDnsResponse(
    message: *const DnsMessage,
    expected_id: u16,
    expected_name: []const u8,
    expected_type: DnsRecordType,
) !void {
    if (message.header.id != expected_id) return error.DnsTransactionMismatch;
    if (!message.header.isResponse()) return error.DnsNotResponse;
    if ((message.header.flags & 0x7800) != 0) return error.DnsInvalidOpcode;
    if (message.questions.len != 1) return error.DnsQuestionMismatch;
    const question = message.questions[0];
    if (!std.ascii.eqlIgnoreCase(question.name, expected_name) or
        question.qtype != expected_type or
        question.qclass != .IN)
    {
        return error.DnsQuestionMismatch;
    }
    if (message.header.isTruncated()) return error.DnsUdpTruncated;
    if (message.header.rcode() == 3 and message.header.isAuthoritative()) {
        return error.AuthoritativeNameError;
    }
    if (message.header.rcode() != 0) return error.DnsResponseError;
    for (message.answers) |answer| {
        if (answer.record_class != .IN) return error.DnsAnswerClassMismatch;
        if (answer.record_type == .A or answer.record_type == .AAAA) {
            if (!dnsAnswerOwnerAllowed(message, answer.name, expected_name)) {
                return error.DnsAnswerOwnerMismatch;
            }
        }
    }
}

fn dnsAnswerOwnerAllowed(
    message: *const DnsMessage,
    owner: []const u8,
    expected_name: []const u8,
) bool {
    var current = expected_name;
    var depth: usize = 0;
    while (depth < 16) : (depth += 1) {
        if (std.ascii.eqlIgnoreCase(owner, current)) return true;
        var next: ?[]const u8 = null;
        for (message.answers) |answer| {
            if (answer.record_type == .CNAME and
                answer.record_class == .IN and
                std.ascii.eqlIgnoreCase(answer.name, current))
            {
                next = answer.rdata;
                break;
            }
        }
        current = next orelse return false;
    }
    return false;
}

fn buildDnsQuery(name: []const u8, qtype: DnsRecordType, use_edns: bool, buf: []u8) !usize {
    var id_bytes: [2]u8 = undefined;
    common.threadIo().random(&id_bytes);
    const id = getU16(&id_bytes);

    var pos: usize = 0;
    putU16(buf[pos..], id);
    pos += 2;

    var flags: u16 = 0;
    flags |= 1 << 8; // RD
    putU16(buf[pos..], flags);
    pos += 2;

    putU16(buf[pos..], 1); // QDCOUNT
    pos += 2;
    putU16(buf[pos..], 0); // ANCOUNT
    pos += 2;
    putU16(buf[pos..], 0); // NSCOUNT
    pos += 2;

    if (use_edns) {
        putU16(buf[pos..], 1); // ARCOUNT
    } else {
        putU16(buf[pos..], 0); // ARCOUNT
    }
    pos += 2;

    const name_result = try encodeDnsName(name, buf[pos..]);
    pos += name_result.len;

    if (pos + 4 > buf.len) return error.BufferTooSmall;
    putU16(buf[pos..], @intFromEnum(qtype));
    pos += 2;
    putU16(buf[pos..], @intFromEnum(DnsRecordClass.IN));
    pos += 2;

    if (use_edns) {
        if (pos + 11 > buf.len) return error.BufferTooSmall;
        buf[pos] = 0; // root label
        pos += 1;
        putU16(buf[pos..], 41); // OPT record type
        pos += 2;
        putU16(buf[pos..], 4096); // UDP payload size
        pos += 2;
        buf[pos] = 0;
        pos += 1;
        buf[pos] = 0;
        pos += 1;
        putU16(buf[pos..], 0); // Z
        pos += 2;
        putU16(buf[pos..], 0); // RDLEN
        pos += 2;
    }

    return pos;
}

fn queryViaUdp(
    server: DnsServer,
    name: []const u8,
    qtype: DnsRecordType,
    timeout_ms: u64,
    allocator: Allocator,
    context: ?*const IoContext,
) !DnsMessage {
    var buf: [4096]u8 = undefined;
    const query_len = try buildDnsQuery(name, qtype, true, &buf);
    const query_id = getU16(buf[0..2]);

    const server_addr = try net.Address.parseIp(server.ip, server.port);
    var sock = socket_mod.UdpSocket.createForAddress(server_addr) catch return error.DnsUdpSocketFailed;
    defer sock.close();

    try sock.connect(server_addr);
    if (context) |caller_context| {
        var query_context = IoContext.init(.{
            .parent = caller_context,
            .phase_deadline = if (timeout_ms > 0) Deadline.afterMs(timeout_ms) else null,
        });
        _ = sock.sendWithContext(buf[0..query_len], &query_context) catch |err| switch (err) {
            error.Cancelled, error.Timeout => return mapQueryContextError(caller_context, err),
            else => return error.DnsUdpSendFailed,
        };
        var resp_buf: [4096]u8 = undefined;
        const n = sock.recvWithContext(&resp_buf, &query_context) catch |err| switch (err) {
            error.Cancelled, error.Timeout => return mapQueryContextError(caller_context, err),
            else => return error.DnsUdpRecvFailed,
        };
        var msg = try parseDnsMessage(resp_buf[0..n], allocator);
        errdefer msg.deinit();
        try validateDnsResponse(&msg, query_id, name, qtype);
        if (msg.header.isTruncated()) return error.DnsUdpTruncated;
        return msg;
    }

    sock.setRecvTimeout(timeout_ms) catch {};
    _ = sock.send(buf[0..query_len]) catch return error.DnsUdpSendFailed;
    var resp_buf: [4096]u8 = undefined;
    const n = sock.recv(&resp_buf) catch return error.DnsUdpRecvFailed;

    var msg = try parseDnsMessage(resp_buf[0..n], allocator);
    errdefer msg.deinit();
    try validateDnsResponse(&msg, query_id, name, qtype);
    if (msg.header.isTruncated()) return error.DnsUdpTruncated;

    return msg;
}

fn queryViaTcp(
    server: DnsServer,
    name: []const u8,
    qtype: DnsRecordType,
    timeout_ms: u64,
    allocator: Allocator,
    context: ?*const IoContext,
) !DnsMessage {
    var buf: [4096]u8 = undefined;
    const query_len = try buildDnsQuery(name, qtype, false, &buf);
    const query_id = getU16(buf[0..2]);

    const server_addr = try net.Address.parseIp(server.ip, server.port);
    var sock = socket_mod.Socket.createForAddress(server_addr) catch return error.DnsTcpSocketFailed;
    defer sock.close();

    var query_context_storage: IoContext = undefined;
    const query_context: ?*IoContext = if (context) |caller_context| blk: {
        query_context_storage = IoContext.init(.{
            .parent = caller_context,
            .phase_deadline = if (timeout_ms > 0) Deadline.afterMs(timeout_ms) else null,
        });
        break :blk &query_context_storage;
    } else null;

    if (query_context) |io_context| {
        sock.connectWithContext(server_addr, timeout_ms, io_context) catch |err| switch (err) {
            error.Cancelled, error.Timeout => return mapQueryContextError(context.?, err),
            else => return error.DnsTcpConnectFailed,
        };
    } else {
        sock.connectWithTimeout(server_addr, timeout_ms) catch return error.DnsTcpConnectFailed;
    }

    var tcp_buf: [4098]u8 = undefined;
    putU16(tcp_buf[0..], @intCast(query_len));
    @memcpy(tcp_buf[2 .. 2 + query_len], buf[0..query_len]);

    if (context) |io_context| {
        _ = io_context;
        sock.sendAllWithContext(tcp_buf[0 .. 2 + query_len], query_context.?) catch |err| switch (err) {
            error.Cancelled, error.Timeout => return mapQueryContextError(context.?, err),
            else => return error.DnsTcpSendFailed,
        };
    } else {
        sock.sendAll(tcp_buf[0 .. 2 + query_len]) catch return error.DnsTcpSendFailed;
    }

    var len_buf: [2]u8 = undefined;
    var read: usize = 0;
    while (read < 2) {
        const n = if (query_context) |io_context|
            sock.recvWithContext(len_buf[read..], io_context) catch |err| switch (err) {
                error.Cancelled, error.Timeout => return mapQueryContextError(context.?, err),
                else => return error.DnsTcpRecvFailed,
            }
        else
            sock.recv(len_buf[read..]) catch return error.DnsTcpRecvFailed;
        if (n == 0) return error.DnsTcpConnectionClosed;
        read += n;
    }

    const resp_len = getU16(&len_buf);
    if (resp_len == 0 or resp_len > 4096) return error.DnsTcpInvalidLength;

    var resp_buf: [4096]u8 = undefined;
    read = 0;
    while (read < resp_len) {
        const n = if (query_context) |io_context|
            sock.recvWithContext(resp_buf[read..resp_len], io_context) catch |err| switch (err) {
                error.Cancelled, error.Timeout => return mapQueryContextError(context.?, err),
                else => return error.DnsTcpRecvFailed,
            }
        else
            sock.recv(resp_buf[read..resp_len]) catch return error.DnsTcpRecvFailed;
        if (n == 0) return error.DnsTcpConnectionClosed;
        read += n;
    }

    var message = try parseDnsMessage(resp_buf[0..resp_len], allocator);
    errdefer message.deinit();
    try validateDnsResponse(&message, query_id, name, qtype);
    return message;
}

fn mapQueryContextError(caller: *const IoContext, err: anyerror) anyerror {
    if (caller.isCancelled()) return error.Cancelled;
    if (caller.expiredDeadline() != null) return error.Timeout;
    if (err == error.Timeout) return error.DnsQueryTimeout;
    return err;
}

fn queryDns(
    servers: []const DnsServer,
    name: []const u8,
    qtype: DnsRecordType,
    udp_timeout_ms: u64,
    tcp_timeout_ms: u64,
    allocator: Allocator,
    context: ?*const IoContext,
    stats_cache: ?*DNSCache,
) !DnsMessage {
    var last_error: ?anyerror = null;
    for (servers) |server| {
        if (stats_cache) |cache| cache.recordUdpQuery();
        if (queryViaUdp(server, name, qtype, udp_timeout_ms, allocator, context)) |msg| {
            return msg;
        } else |udp_error| {
            if (udp_error == error.Cancelled or udp_error == error.Timeout) return udp_error;
            if (udp_error == error.AuthoritativeNameError or udp_error == error.OutOfMemory) {
                return udp_error;
            }
            last_error = udp_error;
            if (stats_cache) |cache| cache.recordTcpQuery();
            if (queryViaTcp(server, name, qtype, tcp_timeout_ms, allocator, context)) |msg| {
                return msg;
            } else |tcp_error| {
                if (tcp_error == error.Cancelled or tcp_error == error.Timeout) return tcp_error;
                if (tcp_error == error.AuthoritativeNameError or tcp_error == error.OutOfMemory) {
                    return tcp_error;
                }
                last_error = tcp_error;
            }
        }
    }
    return last_error orelse error.DnsAllServersFailed;
}

fn extractIpv4Addresses(msg: *DnsMessage, hostname: []const u8, allocator: Allocator) ![]net.Address {
    var addrs = std.ArrayList(net.Address).empty;
    errdefer addrs.deinit(allocator);

    for (msg.answers) |answer| {
        if (answer.record_type == .A and answer.record_class == .IN and answer.rdata.len == 4) {
            const addr = net.Address.initIp4(.{ answer.rdata[0], answer.rdata[1], answer.rdata[2], answer.rdata[3] }, 0);
            try addrs.append(allocator, addr);
        }
    }

    _ = hostname;
    return addrs.toOwnedSlice(allocator);
}

fn extractIpv6Addresses(msg: *DnsMessage, hostname: []const u8, allocator: Allocator) ![]net.Address {
    var addrs = std.ArrayList(net.Address).empty;
    errdefer addrs.deinit(allocator);

    for (msg.answers) |answer| {
        if (answer.record_type == .AAAA and answer.record_class == .IN and answer.rdata.len == 16) {
            const addr = net.Address.initIp6(answer.rdata[0..16].*, 0, 0, 0);
            try addrs.append(allocator, addr);
        }
    }

    _ = hostname;
    return addrs.toOwnedSlice(allocator);
}

const CacheEntry = struct {
    addresses: []net.Address,
    created_at_ms: i64,
    ttl_ms: i64,
};

const NegativeEntry = struct {
    created_at_ms: i64,
    ttl_ms: i64,
};

const CacheLookupResult = union(enum) {
    miss,
    negative,
    positive: []net.Address,
};

const InFlight = struct {
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    ref_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    addresses: []net.Address = &.{},
    failure: ?anyerror = null,
    negative: bool = false,
    allocator: Allocator,

    fn incRef(self: *InFlight) void {
        _ = self.ref_count.fetchAdd(1, .monotonic);
    }

    fn decRef(self: *InFlight) void {
        if (self.ref_count.fetchSub(1, .release) == 1) {
            _ = self.ref_count.load(.acquire);
            self.allocator.free(self.addresses);
            self.allocator.destroy(self);
        }
    }
};

pub const DNSCache = struct {
    allocator: Allocator,
    entries: std.StringHashMapUnmanaged(CacheEntry) = .{},
    negative: std.StringHashMapUnmanaged(NegativeEntry) = .{},
    lru_order: std.ArrayListUnmanaged([]const u8) = .{ .items = &.{}, .capacity = 0 },
    in_flight: std.StringHashMapUnmanaged(*InFlight) = .{},
    lock: std.Io.Mutex = .init,
    config: DNSConfig,
    stats: DNSStats = .{},

    const Self = @This();

    pub fn init(allocator: Allocator, config: DNSConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        {
            self.lock.lock(common.threadIo()) catch {};
            defer self.lock.unlock(common.threadIo());

            var it = self.entries.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*.addresses);
            }
            self.entries.deinit(self.allocator);

            var nit = self.negative.iterator();
            while (nit.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
            }
            self.negative.deinit(self.allocator);

            for (self.lru_order.items) |key| {
                self.allocator.free(key);
            }
            self.lru_order.deinit(self.allocator);

            var iit = self.in_flight.iterator();
            while (iit.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.*.decRef();
            }
            self.in_flight.deinit(self.allocator);
        }
    }

    /// Must be called with `lock` held. Positive results are caller-owned.
    fn cacheLookupOwned(self: *Self, key: []const u8) !CacheLookupResult {
        const now_ms = common.nowMillis();

        if (self.entries.getPtr(key)) |entry| {
            if (now_ms < entry.created_at_ms + entry.ttl_ms) {
                self.touchLRU(key);
                return .{ .positive = try self.allocator.dupe(net.Address, entry.addresses) };
            }
            self.removeEntry(key);
            return .miss;
        }

        if (self.negative.getPtr(key)) |neg| {
            if (now_ms < neg.created_at_ms + neg.ttl_ms) {
                self.stats.negative_hits += 1;
                return .negative;
            }
            self.removeNegative(key);
        }

        return .miss;
    }

    fn cacheStore(self: *Self, key_value: []const u8, addresses: []const net.Address, ttl_ms: i64) void {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());

        self.evictIfNeeded();

        if (self.entries.fetchRemove(key_value)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.addresses);
        }
        self.removeNegative(key_value);

        const key = self.allocator.dupe(u8, key_value) catch return;
        const addrs = self.allocator.dupe(net.Address, addresses) catch {
            self.allocator.free(key);
            return;
        };

        self.entries.put(self.allocator, key, .{
            .addresses = addrs,
            .created_at_ms = common.nowMillis(),
            .ttl_ms = ttl_ms,
        }) catch {
            self.allocator.free(key);
            self.allocator.free(addrs);
            return;
        };

        const lru_key = self.allocator.dupe(u8, key_value) catch return;
        self.lru_order.append(self.allocator, lru_key) catch {
            self.allocator.free(lru_key);
        };
    }

    fn cacheNegative(self: *Self, key_value: []const u8) void {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());

        self.evictIfNeeded();
        self.stats.failures += 1;

        if (self.entries.fetchRemove(key_value)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.addresses);
        }
        self.removeNegative(key_value);

        const key = self.allocator.dupe(u8, key_value) catch return;
        self.negative.put(self.allocator, key, .{
            .created_at_ms = common.nowMillis(),
            .ttl_ms = self.config.negative_ttl_ms,
        }) catch {
            self.allocator.free(key);
        };
    }

    fn evictIfNeeded(self: *Self) void {
        if (self.config.max_cache_entries == 0) return;
        while (self.entries.count() + self.negative.count() >= self.config.max_cache_entries) {
            if (self.lru_order.items.len > 0) {
                const oldest = self.lru_order.orderedRemove(0);
                if (self.entries.fetchRemove(oldest)) |kv| {
                    self.allocator.free(kv.key);
                    self.allocator.free(kv.value.addresses);
                }
                self.allocator.free(oldest);
            } else {
                var negative_it = self.negative.iterator();
                const entry = negative_it.next() orelse break;
                const negative_key = entry.key_ptr.*;
                if (self.negative.fetchRemove(negative_key)) |kv| {
                    self.allocator.free(kv.key);
                }
            }
            self.stats.evictions += 1;
        }
    }

    fn touchLRU(self: *Self, hostname: []const u8) void {
        var i: usize = 0;
        while (i < self.lru_order.items.len) : (i += 1) {
            if (std.mem.eql(u8, self.lru_order.items[i], hostname)) {
                const removed = self.lru_order.orderedRemove(i);
                self.allocator.free(removed);
                break;
            }
        }
        const lru_key = self.allocator.dupe(u8, hostname) catch return;
        self.lru_order.append(self.allocator, lru_key) catch {
            self.allocator.free(lru_key);
        };
    }

    fn removeEntry(self: *Self, hostname: []const u8) void {
        if (self.entries.fetchRemove(hostname)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.addresses);
        }
        var i: usize = 0;
        while (i < self.lru_order.items.len) : (i += 1) {
            if (std.mem.eql(u8, self.lru_order.items[i], hostname)) {
                const removed = self.lru_order.orderedRemove(i);
                self.allocator.free(removed);
                break;
            }
        }
    }

    fn removeNegative(self: *Self, hostname: []const u8) void {
        if (self.negative.fetchRemove(hostname)) |kv| {
            self.allocator.free(kv.key);
        }
    }

    pub fn evictExpired(self: *Self) void {
        const now_ms = common.nowMillis();

        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());

        var expired = std.ArrayList([]const u8).empty;
        defer expired.deinit(self.allocator);

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (now_ms >= entry.value_ptr.created_at_ms + entry.value_ptr.ttl_ms) {
                expired.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (expired.items) |key| {
            self.removeEntry(key);
            self.stats.evictions += 1;
        }

        expired.clearRetainingCapacity();
        var nit = self.negative.iterator();
        while (nit.next()) |entry| {
            if (now_ms >= entry.value_ptr.created_at_ms + entry.value_ptr.ttl_ms) {
                expired.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }
        for (expired.items) |key| {
            self.removeNegative(key);
        }
    }

    pub fn count(self: *Self) u32 {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());
        const pos: u64 = self.entries.count();
        const neg: u64 = self.negative.count();
        return @intCast(@min(pos + neg, @as(u64, std.math.maxInt(u32))));
    }

    pub fn clear(self: *Self) void {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*.addresses);
        }
        self.entries.clearRetainingCapacity();

        var nit = self.negative.iterator();
        while (nit.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.negative.clearRetainingCapacity();

        for (self.lru_order.items) |key| {
            self.allocator.free(key);
        }
        self.lru_order.clearRetainingCapacity();
    }

    pub fn invalidate(self: *Self, hostname: []const u8) void {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());
        self.removeEntry(hostname);
        self.removeNegative(hostname);
        var family_value: u8 = 0;
        while (family_value <= @intFromEnum(AddressFamily.ipv6_only)) : (family_value += 1) {
            var key_buf = std.ArrayList(u8).empty;
            defer key_buf.deinit(self.allocator);
            key_buf.appendSlice(self.allocator, hostname) catch continue;
            key_buf.append(self.allocator, 0) catch continue;
            key_buf.append(self.allocator, family_value) catch continue;
            self.removeEntry(key_buf.items);
            self.removeNegative(key_buf.items);
        }
    }

    pub fn getStats(self: *Self) DNSStats {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());
        return self.stats;
    }

    fn recordLiteralHit(self: *Self) void {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());
        self.stats.literal_hits += 1;
    }

    fn recordUdpQuery(self: *Self) void {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());
        self.stats.udp_queries += 1;
    }

    fn recordTcpQuery(self: *Self) void {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());
        self.stats.tcp_queries += 1;
    }

    fn recordFailure(self: *Self) void {
        self.lock.lock(common.threadIo()) catch {};
        defer self.lock.unlock(common.threadIo());
        self.stats.failures += 1;
    }
};

pub const DNSResolver = struct {
    allocator: Allocator,
    cache: DNSCache,

    const Self = @This();

    pub fn init(allocator: Allocator, config: DNSConfig) Self {
        return .{
            .allocator = allocator,
            .cache = DNSCache.init(allocator, config),
        };
    }

    pub fn deinit(self: *Self) void {
        self.cache.deinit();
    }

    pub const ResolveOptions = struct {
        port: u16 = 0,
        address_family: ?AddressFamily = null,
        address_order: ?AddressOrder = null,
    };

    fn makeCacheKey(self: *Self, hostname: []const u8, family: AddressFamily) ![]u8 {
        const key = try self.allocator.alloc(u8, hostname.len + 2);
        @memcpy(key[0..hostname.len], hostname);
        key[hostname.len] = 0;
        key[hostname.len + 1] = @intFromEnum(family);
        return key;
    }

    pub fn resolve(self: *Self, hostname: []const u8, options: ResolveOptions) !DNSResolution {
        const context = IoContext.init(.{});
        return self.resolveInternal(hostname, options, &context, true);
    }

    /// Resolves a hostname while observing cancellation and the earliest
    /// caller/per-query monotonic deadline.
    pub fn resolveWithContext(
        self: *Self,
        hostname: []const u8,
        options: ResolveOptions,
        context: *const IoContext,
    ) !DNSResolution {
        // A caller-owned cancellation/deadline must not abort shared work and
        // poison unrelated deduplicated waiters. Contextual lookups therefore
        // run independently; the non-contextual resolve() path still dedups.
        return self.resolveInternal(hostname, options, context, false);
    }

    fn resolveInternal(
        self: *Self,
        hostname: []const u8,
        options: ResolveOptions,
        context: *const IoContext,
        allow_dedup: bool,
    ) !DNSResolution {
        try context.check();
        const family = options.address_family orelse self.cache.config.address_family;
        const order = options.address_order orelse self.cache.config.address_order;

        if (address_mod.isIp4Address(hostname)) {
            try context.check();
            self.cache.recordLiteralHit();
            const parsed = try net.Address.parseIp(hostname, options.port);
            const addrs = try self.allocator.alloc(net.Address, 1);
            addrs[0] = parsed;
            return .{
                .hostname = hostname,
                .addresses = addrs,
                .allocator = self.allocator,
            };
        }
        if (address_mod.isIp6Address(hostname)) {
            try context.check();
            self.cache.recordLiteralHit();
            const parsed = try net.Address.parseIp(hostname, options.port);
            const addrs = try self.allocator.alloc(net.Address, 1);
            addrs[0] = parsed;
            return .{
                .hostname = hostname,
                .addresses = addrs,
                .allocator = self.allocator,
            };
        }

        const cache_key = try self.makeCacheKey(hostname, family);
        defer self.allocator.free(cache_key);

        if (self.cache.config.cache_enabled) {
            self.cache.lock.lock(common.threadIo()) catch {};
            const cached = self.cache.cacheLookupOwned(cache_key) catch |err| {
                self.cache.lock.unlock(common.threadIo());
                return err;
            };
            switch (cached) {
                .positive => self.cache.stats.hits += 1,
                .negative => {},
                .miss => self.cache.stats.misses += 1,
            }
            self.cache.lock.unlock(common.threadIo());

            try context.check();
            switch (cached) {
                .positive => |cached_addresses| {
                    defer self.allocator.free(cached_addresses);
                    const addrs = try self.filterAddresses(cached_addresses, family, order);
                    for (addrs) |*a| a.setPort(options.port);
                    return .{
                        .hostname = hostname,
                        .addresses = addrs,
                        .allocator = self.allocator,
                    };
                },
                .negative => return error.DNSLookupFailed,
                .miss => {},
            }
        }

        if (allow_dedup and self.cache.config.dedup_enabled) {
            self.cache.lock.lock(common.threadIo()) catch {};
            if (self.cache.in_flight.getPtr(cache_key)) |inf| {
                inf.*.incRef();
                self.cache.stats.dedup_hits += 1;
                self.cache.lock.unlock(common.threadIo());
                defer inf.*.decRef();

                while (!inf.*.ready.load(.acquire)) {
                    try context.waitForMs(1);
                }
                try context.check();
                const addrs = inf.*.addresses;
                if (inf.*.negative) return error.DNSLookupFailed;
                if (inf.*.failure) |failure| return failure;

                const result_addrs = try self.filterAddresses(addrs, family, order);
                for (result_addrs) |*a| a.setPort(options.port);
                return .{
                    .hostname = hostname,
                    .addresses = result_addrs,
                    .allocator = self.allocator,
                };
            }

            const inf = self.cache.allocator.create(InFlight) catch |err| {
                self.cache.lock.unlock(common.threadIo());
                return err;
            };
            inf.* = .{ .allocator = self.cache.allocator };
            inf.incRef(); // Resolver owner.
            inf.incRef(); // In-flight map.
            const in_flight_key = self.cache.allocator.dupe(u8, cache_key) catch {
                inf.decRef();
                inf.decRef();
                self.cache.lock.unlock(common.threadIo());
                return error.OutOfMemory;
            };
            self.cache.in_flight.put(self.cache.allocator, in_flight_key, inf) catch {
                self.cache.allocator.free(in_flight_key);
                inf.decRef();
                inf.decRef();
                self.cache.lock.unlock(common.threadIo());
                return error.OutOfMemory;
            };
            self.cache.lock.unlock(common.threadIo());
            defer inf.decRef();

            const result = self.performResolution(hostname, family, context);

            self.cache.lock.lock(common.threadIo()) catch {};
            switch (result) {
                .ok => |addrs| {
                    inf.addresses = addrs;
                },
                .negative => inf.negative = true,
                .err => |resolution_error| inf.failure = resolution_error,
            }
            inf.ready.store(true, .release);
            if (self.cache.in_flight.fetchRemove(cache_key)) |kv| {
                self.cache.allocator.free(kv.key);
                kv.value.decRef();
            }
            self.cache.lock.unlock(common.threadIo());

            try context.check();
            if (self.cache.config.cache_enabled and !inf.negative and inf.failure == null) {
                self.cache.cacheStore(cache_key, inf.addresses, self.cache.config.positive_ttl_ms);
            }
            if (inf.negative) {
                if (self.cache.config.cache_enabled) {
                    self.cache.cacheNegative(cache_key);
                } else {
                    self.cache.recordFailure();
                }
                return error.DNSLookupFailed;
            }
            if (inf.failure) |failure| {
                self.cache.recordFailure();
                return failure;
            }

            const addrs = try self.filterAddresses(inf.addresses, family, order);
            for (addrs) |*a| a.setPort(options.port);
            return .{
                .hostname = hostname,
                .addresses = addrs,
                .allocator = self.allocator,
            };
        }

        try context.check();
        const result = self.performResolution(hostname, family, context);

        switch (result) {
            .ok => |addrs| {
                defer self.allocator.free(addrs);
                try context.check();
                if (self.cache.config.cache_enabled) {
                    self.cache.cacheStore(cache_key, addrs, self.cache.config.positive_ttl_ms);
                }
                const out = try self.filterAddresses(addrs, family, order);
                for (out) |*a| a.setPort(options.port);
                return .{
                    .hostname = hostname,
                    .addresses = out,
                    .allocator = self.allocator,
                };
            },
            .negative => {
                if (self.cache.config.cache_enabled) self.cache.cacheNegative(cache_key);
                return error.DNSLookupFailed;
            },
            .err => |resolution_error| {
                if (resolution_error == error.Cancelled or resolution_error == error.Timeout) {
                    return resolution_error;
                }
                self.cache.recordFailure();
                try context.check();
                return resolution_error;
            },
        }
    }

    pub fn resolveAll(self: *Self, hostname: []const u8, options: ResolveOptions) !DNSResolution {
        const context = IoContext.init(.{});
        return self.resolveAllWithContext(hostname, options, &context);
    }

    /// Context-aware counterpart to `resolve`.
    pub fn resolveAllWithContext(
        self: *Self,
        hostname: []const u8,
        options: ResolveOptions,
        context: *const IoContext,
    ) !DNSResolution {
        return self.resolveInternal(hostname, options, context, false);
    }

    pub fn invalidate(self: *Self, hostname: []const u8) void {
        self.cache.invalidate(hostname);
    }

    pub fn clear(self: *Self) void {
        self.cache.clear();
    }

    pub fn evictExpired(self: *Self) void {
        self.cache.evictExpired();
    }

    pub fn getStats(self: *Self) DNSStats {
        return self.cache.getStats();
    }

    const ResolveResult = union(enum) {
        ok: []net.Address,
        negative,
        err: anyerror,
    };

    fn terminalCnameTarget(message: *const DnsMessage, start: []const u8) !?[]const u8 {
        var current = start;
        var changed = false;
        var depth: usize = 0;
        while (depth < 8) : (depth += 1) {
            var next: ?[]const u8 = null;
            for (message.answers) |answer| {
                if (answer.record_type == .CNAME and
                    std.ascii.eqlIgnoreCase(answer.name, current))
                {
                    if (next != null and !std.ascii.eqlIgnoreCase(next.?, answer.rdata)) {
                        return error.DnsCnameConflict;
                    }
                    next = answer.rdata;
                }
            }
            const target = next orelse break;
            if (std.ascii.eqlIgnoreCase(target, start)) return error.DnsCnameLoop;
            current = target;
            changed = true;
        }
        if (depth == 8) return error.DnsCnameDepthExceeded;
        return if (changed) current else null;
    }

    fn resolveRecordType(
        self: *Self,
        hostname: []const u8,
        record_type: DnsRecordType,
        context: ?*const IoContext,
    ) ResolveResult {
        var current = self.allocator.dupe(u8, hostname) catch |err| return .{ .err = err };
        defer self.allocator.free(current);
        var visited = std.ArrayList([]u8).empty;
        defer {
            for (visited.items) |name| self.allocator.free(name);
            visited.deinit(self.allocator);
        }

        for (0..8) |_| {
            for (visited.items) |name| {
                if (std.ascii.eqlIgnoreCase(name, current)) {
                    return .{ .err = error.DnsCnameLoop };
                }
            }
            const visited_name = self.allocator.dupe(u8, current) catch |err|
                return .{ .err = err };
            visited.append(self.allocator, visited_name) catch |err| {
                self.allocator.free(visited_name);
                return .{ .err = err };
            };

            var message = queryDns(
                self.cache.config.dns_servers,
                current,
                record_type,
                self.cache.config.udp_timeout_ms,
                self.cache.config.tcp_timeout_ms,
                self.allocator,
                context,
                &self.cache,
            ) catch |err| {
                if (err == error.AuthoritativeNameError) return .negative;
                return .{ .err = err };
            };
            defer message.deinit();

            const addresses = if (record_type == .A)
                extractIpv4Addresses(&message, current, self.allocator)
            else
                extractIpv6Addresses(&message, current, self.allocator);
            const resolved = addresses catch |err| return .{ .err = err };
            if (resolved.len > 0) return .{ .ok = resolved };
            self.allocator.free(resolved);

            const target = terminalCnameTarget(&message, current) catch |err|
                return .{ .err = err };
            if (target) |canonical| {
                const next = self.allocator.dupe(u8, canonical) catch |err|
                    return .{ .err = err };
                self.allocator.free(current);
                current = next;
                continue;
            }
            return if (message.header.isAuthoritative())
                .negative
            else
                .{ .err = error.DNSNoData };
        }
        return .{ .err = error.DnsCnameDepthExceeded };
    }

    fn performResolution(
        self: *Self,
        hostname: []const u8,
        family: AddressFamily,
        context: ?*const IoContext,
    ) ResolveResult {
        var all_addrs = std.ArrayList(net.Address).empty;
        defer all_addrs.deinit(self.allocator);

        const should_query_v4 = family == .any or family == .ipv4_only;
        const should_query_v6 = family == .any or family == .ipv6_only;
        var query_count: u8 = 0;
        var authoritative_no_data: u8 = 0;
        var first_error: ?anyerror = null;

        if (should_query_v4) {
            query_count += 1;
            switch (self.resolveRecordType(hostname, .A, context)) {
                .ok => |addresses| {
                    defer self.allocator.free(addresses);
                    all_addrs.appendSlice(self.allocator, addresses) catch |err|
                        return .{ .err = err };
                },
                .negative => authoritative_no_data += 1,
                .err => |err| {
                    if (err == error.Cancelled or err == error.Timeout) return .{ .err = err };
                    if (first_error == null) first_error = err;
                },
            }
        }

        if (should_query_v6) {
            query_count += 1;
            switch (self.resolveRecordType(hostname, .AAAA, context)) {
                .ok => |addresses| {
                    defer self.allocator.free(addresses);
                    all_addrs.appendSlice(self.allocator, addresses) catch |err|
                        return .{ .err = err };
                },
                .negative => authoritative_no_data += 1,
                .err => |err| {
                    if (err == error.Cancelled or err == error.Timeout) return .{ .err = err };
                    if (first_error == null) first_error = err;
                },
            }
        }

        if (all_addrs.items.len == 0) {
            if (query_count > 0 and authoritative_no_data == query_count) return .negative;
            return .{ .err = first_error orelse error.DNSResolutionFailed };
        }

        const addrs = self.allocator.dupe(net.Address, all_addrs.items) catch {
            return .{ .err = error.OutOfMemory };
        };
        return .{ .ok = addrs };
    }

    fn filterAddresses(
        self: *Self,
        addrs: []const net.Address,
        family: AddressFamily,
        order: AddressOrder,
    ) ![]net.Address {
        var count: usize = 0;
        for (addrs) |addr| {
            if ((family == .any) or
                (family == .ipv4_only and addr.any.family == std.posix.AF.INET) or
                (family == .ipv6_only and addr.any.family == std.posix.AF.INET6))
            {
                count += 1;
            }
        }
        const result = try self.allocator.alloc(net.Address, count);
        var index: usize = 0;
        if (family == .any and order == .system) {
            @memcpy(result, addrs[0..count]);
            return result;
        }
        const preferred_family: ?u16 = switch (family) {
            .ipv4_only => std.posix.AF.INET,
            .ipv6_only => std.posix.AF.INET6,
            .any => switch (order) {
                .ipv6_preferred => std.posix.AF.INET6,
                .system, .ipv4_preferred => std.posix.AF.INET,
            },
        };
        for (addrs) |addr| {
            if (addr.any.family == preferred_family.?) {
                result[index] = addr;
                index += 1;
            }
        }
        if (family == .any) {
            for (addrs) |addr| {
                if (addr.any.family != preferred_family.?) {
                    result[index] = addr;
                    index += 1;
                }
            }
        }
        return result;
    }
};

fn dnsTestWorker(resolver: *DNSResolver, thread_id: u32) void {
    for (0..50) |i| {
        const name = std.fmt.allocPrint(
            std.heap.page_allocator,
            "thread{d}-host{d}.com",
            .{ thread_id, i },
        ) catch continue;
        defer std.heap.page_allocator.free(name);

        var addresses = [_]net.Address{
            net.Address.initIp4(.{ 127, 0, 0, @intCast(i + 1) }, 80),
        };
        resolver.cache.cacheStore(name, &addresses, resolver.cache.config.positive_ttl_ms);
        _ = resolver.cache.count();
        resolver.invalidate(name);
    }
}

test "DNSConfig defaults" {
    const cfg = DNSConfig{};
    try std.testing.expectEqual(@as(i64, 60_000), cfg.positive_ttl_ms);
    try std.testing.expectEqual(@as(i64, 5_000), cfg.negative_ttl_ms);
    try std.testing.expectEqual(@as(u32, 1024), cfg.max_cache_entries);
    try std.testing.expectEqual(AddressFamily.any, cfg.address_family);
    try std.testing.expectEqual(AddressOrder.system, cfg.address_order);
    try std.testing.expect(cfg.cache_enabled);
    try std.testing.expect(cfg.dedup_enabled);
}

test "DNSResolution ok/failed" {
    const allocator = std.testing.allocator;
    const addrs = try allocator.alloc(net.Address, 1);
    addrs[0] = net.Address.initIp4(.{ 8, 8, 8, 8 }, 80);

    var res = DNSResolution{
        .hostname = "example.com",
        .addresses = addrs,
        .allocator = allocator,
    };
    try std.testing.expect(res.ok());
    res.deinit();

    var fail = DNSResolution{
        .hostname = "bad.host",
        .addresses = &.{},
        .failed = true,
        .allocator = allocator,
    };
    try std.testing.expect(!fail.ok());
}

test "DNSStats hitRate" {
    var stats = DNSStats{};
    try std.testing.expectEqual(@as(f64, 0.0), stats.hitRate());
    stats.hits = 7;
    stats.misses = 3;
    try std.testing.expectApproxEqAbs(@as(f64, 0.7), stats.hitRate(), 0.001);
}

test "DNSCache init and deinit" {
    var cache = DNSCache.init(std.testing.allocator, .{});
    defer cache.deinit();
    try std.testing.expectEqual(@as(u32, 0), cache.count());
}

test "DNSCache clear" {
    var cache = DNSCache.init(std.testing.allocator, .{});
    defer cache.deinit();

    const key1 = try std.testing.allocator.dupe(u8, "example1.com");
    const addrs1 = try std.testing.allocator.alloc(net.Address, 1);
    addrs1[0] = net.Address.initIp4(.{ 1, 2, 3, 4 }, 80);
    cache.entries.put(std.testing.allocator, key1, .{
        .addresses = addrs1,
        .created_at_ms = common.nowMillis(),
        .ttl_ms = 60_000,
    }) catch {
        std.testing.allocator.free(key1);
        std.testing.allocator.free(addrs1);
    };

    try std.testing.expectEqual(@as(u32, 1), cache.count());
    cache.clear();
    try std.testing.expectEqual(@as(u32, 0), cache.count());
}

test "DNSCache evictExpired" {
    var cache = DNSCache.init(std.testing.allocator, .{});
    defer cache.deinit();

    const key1 = try std.testing.allocator.dupe(u8, "expired.com");
    const addrs1 = try std.testing.allocator.alloc(net.Address, 1);
    addrs1[0] = net.Address.initIp4(.{ 1, 2, 3, 4 }, 80);
    cache.entries.put(std.testing.allocator, key1, .{
        .addresses = addrs1,
        .created_at_ms = 0,
        .ttl_ms = 1,
    }) catch {
        std.testing.allocator.free(key1);
        std.testing.allocator.free(addrs1);
    };

    const key2 = try std.testing.allocator.dupe(u8, "valid.com");
    const addrs2 = try std.testing.allocator.alloc(net.Address, 1);
    addrs2[0] = net.Address.initIp4(.{ 5, 6, 7, 8 }, 80);
    cache.entries.put(std.testing.allocator, key2, .{
        .addresses = addrs2,
        .created_at_ms = common.nowMillis(),
        .ttl_ms = 60_000,
    }) catch {
        std.testing.allocator.free(key2);
        std.testing.allocator.free(addrs2);
    };

    try std.testing.expectEqual(@as(u32, 2), cache.count());
    cache.evictExpired();
    try std.testing.expectEqual(@as(u32, 1), cache.count());
}

test "DNSCache max_entries LRU eviction" {
    var cache = DNSCache.init(std.testing.allocator, .{ .max_cache_entries = 2 });
    defer cache.deinit();

    for (0..2) |i| {
        const key = try std.fmt.allocPrint(std.testing.allocator, "host{d}.com", .{i});
        const addrs = try std.testing.allocator.alloc(net.Address, 1);
        addrs[0] = net.Address.initIp4(.{ 1, 0, 0, @intCast(i) }, 80);
        cache.entries.put(std.testing.allocator, key, .{
            .addresses = addrs,
            .created_at_ms = common.nowMillis(),
            .ttl_ms = 60_000,
        }) catch {
            std.testing.allocator.free(key);
            std.testing.allocator.free(addrs);
        };
        const lru_key = try std.testing.allocator.dupe(u8, key);
        cache.lru_order.append(std.testing.allocator, lru_key) catch {
            std.testing.allocator.free(lru_key);
        };
    }

    try std.testing.expectEqual(@as(u32, 2), cache.count());

    const key_new = try std.testing.allocator.dupe(u8, "newhost.com");
    const addrs_new = try std.testing.allocator.alloc(net.Address, 1);
    addrs_new[0] = net.Address.initIp4(.{ 9, 9, 9, 9 }, 80);
    cache.evictIfNeeded();
    cache.entries.put(std.testing.allocator, key_new, .{
        .addresses = addrs_new,
        .created_at_ms = common.nowMillis(),
        .ttl_ms = 60_000,
    }) catch {
        std.testing.allocator.free(key_new);
        std.testing.allocator.free(addrs_new);
    };

    try std.testing.expect(cache.count() <= 2);
}

test "DNSCache invalidate" {
    var cache = DNSCache.init(std.testing.allocator, .{});
    defer cache.deinit();

    const key = try std.testing.allocator.dupe(u8, "example.com");
    const addrs = try std.testing.allocator.alloc(net.Address, 1);
    addrs[0] = net.Address.initIp4(.{ 1, 2, 3, 4 }, 80);
    cache.entries.put(std.testing.allocator, key, .{
        .addresses = addrs,
        .created_at_ms = common.nowMillis(),
        .ttl_ms = 60_000,
    }) catch {
        std.testing.allocator.free(key);
        std.testing.allocator.free(addrs);
    };

    try std.testing.expectEqual(@as(u32, 1), cache.count());
    cache.invalidate("example.com");
    try std.testing.expectEqual(@as(u32, 0), cache.count());
}

test "DNSCache negative cache" {
    var cache = DNSCache.init(std.testing.allocator, .{ .negative_ttl_ms = 1000 });
    defer cache.deinit();

    cache.cacheNegative("nonexistent.host");
    try std.testing.expectEqual(@as(u32, 1), cache.count());
    try std.testing.expectEqual(@as(u64, 1), cache.stats.failures);
}

test "DNSResolver init and deinit" {
    var resolver = DNSResolver.init(std.testing.allocator, .{});
    defer resolver.deinit();
}

test "DNSResolver resolve IP literal" {
    var resolver = DNSResolver.init(std.testing.allocator, .{ .cache_enabled = false });
    defer resolver.deinit();

    var res = try resolver.resolve("127.0.0.1", .{ .port = 80 });
    defer res.deinit();
    try std.testing.expect(res.ok());
    try std.testing.expectEqual(@as(usize, 1), res.addresses.len);

    var res6 = try resolver.resolve("::1", .{ .port = 443 });
    defer res6.deinit();
    try std.testing.expect(res6.ok());
    try std.testing.expectEqual(@as(usize, 1), res6.addresses.len);
}

test "DNSResolver context checks cancellation before cache or lookup" {
    var resolver = DNSResolver.init(std.testing.allocator, .{});
    defer resolver.deinit();

    var token = CancellationToken.init();
    token.cancel();
    const context = IoContext.init(.{ .external_cancel = &token });

    try std.testing.expectError(
        error.Cancelled,
        resolver.resolveWithContext("127.0.0.1", .{ .port = 80 }, &context),
    );
    try std.testing.expectEqual(@as(u64, 0), resolver.cache.stats.literal_hits);
}

test "DNSResolver cancellation interrupts an in-flight UDP query" {
    var dns_socket = try socket_mod.UdpSocket.create();
    defer dns_socket.close();
    try dns_socket.bind(try net.Address.parseIp("127.0.0.1", 0));
    try dns_socket.setRecvTimeout(5_000);
    const dns_address = try dns_socket.getLocalAddress();
    const servers = [_]DnsServer{.{ .ip = "127.0.0.1", .port = dns_address.getPort() }};

    var resolver = DNSResolver.init(std.testing.allocator, .{
        .cache_enabled = false,
        .dedup_enabled = false,
        .address_family = .ipv4_only,
        .dns_servers = &servers,
        .udp_timeout_ms = 30_000,
        .tcp_timeout_ms = 30_000,
    });
    defer resolver.deinit();

    var token = CancellationToken.init();
    const context = IoContext.init(.{ .external_cancel = &token });
    const Worker = struct {
        resolver: *DNSResolver,
        context: *const IoContext,
        result: ?anyerror = null,

        fn run(self: *@This()) void {
            var resolution = self.resolver.resolveWithContext(
                "cancel-during-udp.invalid",
                .{ .port = 80 },
                self.context,
            ) catch |err| {
                self.result = err;
                return;
            };
            resolution.deinit();
            self.result = error.TestUnexpectedResult;
        }
    };

    var worker = Worker{ .resolver = &resolver, .context = &context };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var response_buffer: [4096]u8 = undefined;
    _ = try dns_socket.recvFrom(&response_buffer);
    token.cancel();
    thread.join();

    try std.testing.expectEqual(error.Cancelled, worker.result.?);
    try std.testing.expectEqual(@as(u64, 0), resolver.getStats().failures);
}

test "DNS UDP query uses earliest caller and per-query deadlines" {
    var dns_socket = try socket_mod.UdpSocket.create();
    defer dns_socket.close();
    try dns_socket.bind(try net.Address.parseIp("127.0.0.1", 0));
    const address = try dns_socket.getLocalAddress();
    const server = DnsServer{ .ip = "127.0.0.1", .port = address.getPort() };

    const no_caller_deadline = IoContext.init(.{});
    try std.testing.expectError(
        error.DnsQueryTimeout,
        queryViaUdp(server, "query-timeout.invalid", .A, 20, std.testing.allocator, &no_caller_deadline),
    );

    const caller_deadline = IoContext.init(.{ .phase_deadline = Deadline.afterMs(10) });
    try std.testing.expectError(
        error.Timeout,
        queryViaUdp(server, "caller-timeout.invalid", .A, 5_000, std.testing.allocator, &caller_deadline),
    );
}

test "DNS TCP query enforces its per-query deadline" {
    var listener = try socket_mod.TcpListener.init(try net.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const address = try listener.getLocalAddress();

    const Server = struct {
        listener: *socket_mod.TcpListener,
        accepted: std.atomic.Value(bool) = .init(false),
        release: std.atomic.Value(bool) = .init(false),
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.listener.accept() catch |err| {
                self.failure = err;
                return;
            };
            defer connection.socket.close();
            self.accepted.store(true, .release);
            while (!self.release.load(.acquire)) std.Thread.yield() catch {};
        }
    };

    var server_state = Server{ .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Server.run, .{&server_state});
    var joined = false;
    defer if (!joined) {
        server_state.release.store(true, .release);
        thread.join();
    };

    const context = IoContext.init(.{});
    try std.testing.expectError(
        error.DnsQueryTimeout,
        queryViaTcp(
            .{ .ip = "127.0.0.1", .port = address.getPort() },
            "tcp-timeout.invalid",
            .A,
            20,
            std.testing.allocator,
            &context,
        ),
    );
    server_state.release.store(true, .release);
    thread.join();
    joined = true;
    try std.testing.expect(server_state.failure == null);
    try std.testing.expect(server_state.accepted.load(.acquire));
}

test "DNSResolver cancellable lookup does not join or poison shared dedup work" {
    const allocator = std.testing.allocator;
    var resolver = DNSResolver.init(allocator, .{
        .cache_enabled = false,
        .dedup_enabled = true,
    });
    defer resolver.deinit();

    const in_flight = try allocator.create(InFlight);
    in_flight.* = .{ .allocator = allocator };
    in_flight.incRef();
    const key = try allocator.dupe(u8, "dedup.test");
    try resolver.cache.in_flight.put(allocator, key, in_flight);

    var token = CancellationToken.init();
    token.cancel();
    const context = IoContext.init(.{ .external_cancel = &token });
    const result = resolver.resolveWithContext("dedup.test", .{}, &context);

    try std.testing.expectError(error.Cancelled, result);
    try std.testing.expectEqual(@as(u32, 1), in_flight.ref_count.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), resolver.getStats().dedup_hits);
}

test "DNSResolver resolveAll IP literal" {
    var resolver = DNSResolver.init(std.testing.allocator, .{ .cache_enabled = false });
    defer resolver.deinit();

    var res = try resolver.resolveAll("10.0.0.1", .{ .port = 8080 });
    defer res.deinit();
    try std.testing.expect(res.ok());
    try std.testing.expectEqual(@as(usize, 1), res.addresses.len);
}

test "AddressFamily filtering" {
    var resolver = DNSResolver.init(std.testing.allocator, .{});
    defer resolver.deinit();

    var addrs = [_]net.Address{
        net.Address.initIp4(.{ 1, 2, 3, 4 }, 80),
        net.Address.initIp6(.{ 0x20, 0x01, 0xdb, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 80, 0, 0),
        net.Address.initIp4(.{ 5, 6, 7, 8 }, 80),
    };

    const any_filtered = try resolver.filterAddresses(&addrs, .any, .system);
    defer std.testing.allocator.free(any_filtered);
    try std.testing.expectEqual(@as(usize, 3), any_filtered.len);

    const v4_filtered = try resolver.filterAddresses(&addrs, .ipv4_only, .system);
    defer std.testing.allocator.free(v4_filtered);
    try std.testing.expectEqual(@as(usize, 2), v4_filtered.len);

    const v6_filtered = try resolver.filterAddresses(&addrs, .ipv6_only, .system);
    defer std.testing.allocator.free(v6_filtered);
    try std.testing.expectEqual(@as(usize, 1), v6_filtered.len);
}

test "AddressOrder" {
    var resolver = DNSResolver.init(std.testing.allocator, .{});
    defer resolver.deinit();

    var addrs = [_]net.Address{
        net.Address.initIp4(.{ 1, 2, 3, 4 }, 80),
        net.Address.initIp6(.{ 0x20, 0x01, 0xdb, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 80, 0, 0),
    };

    const v4_pref = try resolver.filterAddresses(&addrs, .any, .ipv4_preferred);
    defer std.testing.allocator.free(v4_pref);
    try std.testing.expect(v4_pref.len >= 2);

    const v6_pref = try resolver.filterAddresses(&addrs, .any, .ipv6_preferred);
    defer std.testing.allocator.free(v6_pref);
    try std.testing.expect(v6_pref.len >= 2);
}

test "DNSCache thread safety" {
    var resolver = DNSResolver.init(std.testing.allocator, .{ .cache_enabled = true, .max_cache_entries = 100 });
    defer resolver.deinit();

    var threads: [4]std.Thread = undefined;
    for (0..4) |t| {
        threads[t] = std.Thread.spawn(.{}, dnsTestWorker, .{ &resolver, @as(u32, @intCast(t)) }) catch continue;
    }
    for (threads) |t| {
        t.join();
    }

    const count = resolver.cache.count();
    try std.testing.expect(count <= 100);
}

test "DNSResolver getStats" {
    var resolver = DNSResolver.init(std.testing.allocator, .{});
    defer resolver.deinit();

    var res = try resolver.resolve("127.0.0.1", .{});
    defer res.deinit();

    const stats = resolver.getStats();
    try std.testing.expect(stats.literal_hits > 0);
}

test "encodeDnsName basic" {
    var buf: [256]u8 = undefined;
    const result = try encodeDnsName("example.com", &buf);
    try std.testing.expectEqual(@as(usize, 13), result.len);
    try std.testing.expectEqual(@as(u8, 7), buf[0]);
    try std.testing.expectEqualStrings("example", buf[1..8]);
    try std.testing.expectEqual(@as(u8, 3), buf[8]);
    try std.testing.expectEqualStrings("com", buf[9..12]);
    try std.testing.expectEqual(@as(u8, 0), buf[12]);
}

test "decodeDnsName basic" {
    var buf: [256]u8 = undefined;
    const result = try encodeDnsName("example.com", &buf);

    var offset: usize = 0;
    var out: [256]u8 = undefined;
    const name_len = try decodeDnsName(buf[0..result.len], &offset, &out);
    try std.testing.expectEqualStrings("example.com", out[0..name_len]);
}

test "buildDnsQuery header" {
    var buf: [512]u8 = undefined;
    const len = try buildDnsQuery("example.com", .A, false, &buf);
    try std.testing.expect(len >= 12);

    const flags = getU16(buf[2..4]);
    try std.testing.expect((flags & (1 << 8)) != 0); // RD set

    const qdcount = getU16(buf[4..6]);
    try std.testing.expectEqual(@as(u16, 1), qdcount);

    const ancount = getU16(buf[6..8]);
    try std.testing.expectEqual(@as(u16, 0), ancount);
}

test "parseDnsMessage header" {
    var buf: [256]u8 = undefined;
    const len = try buildDnsQuery("test.com", .A, false, &buf);

    var msg = try parseDnsMessage(buf[0..len], std.testing.allocator);
    defer msg.deinit();

    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);
    try std.testing.expectEqual(@as(u16, 0), msg.header.ancount);
    try std.testing.expectEqual(@as(usize, 1), msg.questions.len);
    try std.testing.expectEqualStrings("test.com", msg.questions[0].name);
    try std.testing.expectEqual(DnsRecordType.A, msg.questions[0].qtype);
}

test "DNS wire query initializes QCLASS and EDNS RDLEN" {
    var buffer: [512]u8 = undefined;
    @memset(&buffer, 0xaa);
    const len = try buildDnsQuery("example.com", .A, true, &buffer);
    var offset: usize = 12;
    var name: [256]u8 = undefined;
    _ = try decodeDnsName(buffer[0..len], &offset, &name);
    try std.testing.expectEqual(@intFromEnum(DnsRecordType.A), getU16(buffer[offset..][0..2]));
    try std.testing.expectEqual(@intFromEnum(DnsRecordClass.IN), getU16(buffer[offset + 2 ..][0..2]));
    offset += 4;
    try std.testing.expectEqual(@as(u8, 0), buffer[offset]);
    try std.testing.expectEqual(@as(u16, 41), getU16(buffer[offset + 1 ..][0..2]));
    try std.testing.expectEqual(@as(u16, 0), getU16(buffer[len - 2 .. len]));
}

test "DNS response validation checks transaction question and compressed answer owner" {
    var wire: [512]u8 = undefined;
    @memset(&wire, 0);
    putU16(wire[0..2], 0x1234);
    putU16(wire[2..4], 0x8180);
    putU16(wire[4..6], 1);
    putU16(wire[6..8], 1);
    var offset: usize = 12;
    offset += (try encodeDnsName("example.com", wire[offset..])).len;
    putU16(wire[offset..], @intFromEnum(DnsRecordType.A));
    putU16(wire[offset + 2 ..], @intFromEnum(DnsRecordClass.IN));
    offset += 4;
    wire[offset] = 0xc0;
    wire[offset + 1] = 0x0c;
    offset += 2;
    putU16(wire[offset..], @intFromEnum(DnsRecordType.A));
    putU16(wire[offset + 2 ..], @intFromEnum(DnsRecordClass.IN));
    putU32(wire[offset + 4 ..], 60);
    putU16(wire[offset + 8 ..], 4);
    offset += 10;
    wire[offset..][0..4].* = .{ 127, 0, 0, 1 };
    offset += 4;

    var message = try parseDnsMessage(wire[0..offset], std.testing.allocator);
    defer message.deinit();
    try validateDnsResponse(&message, 0x1234, "example.com", .A);
    try std.testing.expectEqualStrings("example.com", message.answers[0].name);

    try std.testing.expectError(
        error.DnsTransactionMismatch,
        validateDnsResponse(&message, 0x1235, "example.com", .A),
    );
    try std.testing.expectError(
        error.DnsQuestionMismatch,
        validateDnsResponse(&message, 0x1234, "other.example", .A),
    );
    const original_owner = message.answers[0].name;
    message.answers[0].name = "attacker.example";
    try std.testing.expectError(
        error.DnsAnswerOwnerMismatch,
        validateDnsResponse(&message, 0x1234, "example.com", .A),
    );
    message.answers[0].name = original_owner;

    message.header.flags = 0x8403;
    try std.testing.expectError(
        error.AuthoritativeNameError,
        validateDnsResponse(&message, 0x1234, "example.com", .A),
    );
    message.header.flags = 0x8603;
    try std.testing.expectError(
        error.DnsUdpTruncated,
        validateDnsResponse(&message, 0x1234, "example.com", .A),
    );
    message.header.flags = 0x8182;
    try std.testing.expectError(
        error.DnsResponseError,
        validateDnsResponse(&message, 0x1234, "example.com", .A),
    );
}

test "DNS CNAME-only responses follow a bounded validated terminal chain" {
    const answers = [_]DnsRecord{
        .{
            .name = "alias.test",
            .record_type = .CNAME,
            .record_class = .IN,
            .ttl = 60,
            .rdata = "middle.test",
        },
        .{
            .name = "middle.test",
            .record_type = .CNAME,
            .record_class = .IN,
            .ttl = 60,
            .rdata = "terminal.test",
        },
    };
    const message = DnsMessage{
        .header = .{
            .id = 1,
            .flags = 0x8400,
            .qdcount = 1,
            .ancount = 2,
            .nscount = 0,
            .arcount = 0,
        },
        .questions = &.{},
        .answers = @constCast(&answers),
        .allocator = std.testing.allocator,
    };
    try std.testing.expectEqualStrings(
        "terminal.test",
        (try DNSResolver.terminalCnameTarget(&message, "alias.test")).?,
    );

    var loop_answers = answers;
    loop_answers[1].rdata = "alias.test";
    var loop_message = message;
    loop_message.answers = &loop_answers;
    try std.testing.expectError(
        error.DnsCnameLoop,
        DNSResolver.terminalCnameTarget(&loop_message, "alias.test"),
    );
}

test "DNS parsing is allocation safe for partial arrays" {
    const Case = struct {
        fn run(allocator: Allocator) !void {
            var wire: [512]u8 = undefined;
            @memset(&wire, 0);
            putU16(wire[0..2], 0x1234);
            putU16(wire[2..4], 0x8180);
            putU16(wire[4..6], 1);
            putU16(wire[6..8], 1);
            var offset: usize = 12;
            offset += (try encodeDnsName("example.com", wire[offset..])).len;
            putU16(wire[offset..], @intFromEnum(DnsRecordType.A));
            putU16(wire[offset + 2 ..], @intFromEnum(DnsRecordClass.IN));
            offset += 4;
            wire[offset] = 0xc0;
            wire[offset + 1] = 0x0c;
            offset += 2;
            putU16(wire[offset..], @intFromEnum(DnsRecordType.A));
            putU16(wire[offset + 2 ..], @intFromEnum(DnsRecordClass.IN));
            putU16(wire[offset + 8 ..], 4);
            offset += 10;
            wire[offset..][0..4].* = .{ 1, 2, 3, 4 };
            offset += 4;
            var message = try parseDnsMessage(wire[0..offset], allocator);
            defer message.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.run, .{});

    var truncated: [32]u8 = [_]u8{0} ** 32;
    putU16(truncated[4..6], 2);
    try std.testing.expectError(
        error.InvalidDnsName,
        parseDnsMessage(truncated[0..17], std.testing.allocator),
    );
}

test "DNS cache lookup clones addresses before concurrent invalidation" {
    var cache = DNSCache.init(std.testing.allocator, .{});
    defer cache.deinit();
    const addresses = [_]net.Address{net.Address.initIp4(.{ 127, 0, 0, 1 }, 80)};
    cache.cacheStore("race.test", &addresses, 60_000);

    const Shared = struct {
        cache: *DNSCache,
        failure: ?anyerror = null,

        fn reader(self: *@This()) void {
            for (0..500) |_| {
                self.cache.lock.lock(common.threadIo()) catch continue;
                const copy = self.cache.cacheLookupOwned("race.test") catch |err| {
                    self.cache.lock.unlock(common.threadIo());
                    self.failure = err;
                    return;
                };
                self.cache.lock.unlock(common.threadIo());
                switch (copy) {
                    .positive => |owned| {
                        if (owned.len != 1) self.failure = error.TestUnexpectedResult;
                        self.cache.allocator.free(owned);
                    },
                    .miss, .negative => {},
                }
            }
        }

        fn writer(self: *@This()) void {
            const replacement = [_]net.Address{
                net.Address.initIp4(.{ 127, 0, 0, 1 }, 80),
            };
            for (0..500) |_| {
                self.cache.invalidate("race.test");
                self.cache.cacheStore("race.test", &replacement, 60_000);
            }
        }
    };
    var shared = Shared{ .cache = &cache };
    const reader = try std.Thread.spawn(.{}, Shared.reader, .{&shared});
    const writer = try std.Thread.spawn(.{}, Shared.writer, .{&shared});
    reader.join();
    writer.join();
    try std.testing.expect(shared.failure == null);
}

test "DNS cache and dedup keys include address family" {
    var resolver = DNSResolver.init(std.testing.allocator, .{});
    defer resolver.deinit();
    const any_key = try resolver.makeCacheKey("family.test", .any);
    defer std.testing.allocator.free(any_key);
    const v4_key = try resolver.makeCacheKey("family.test", .ipv4_only);
    defer std.testing.allocator.free(v4_key);
    const v6_key = try resolver.makeCacheKey("family.test", .ipv6_only);
    defer std.testing.allocator.free(v6_key);
    try std.testing.expect(!std.mem.eql(u8, any_key, v4_key));
    try std.testing.expect(!std.mem.eql(u8, v4_key, v6_key));

    const addresses = [_]net.Address{net.Address.initIp4(.{ 127, 0, 0, 1 }, 0)};
    resolver.cache.cacheStore(v4_key, &addresses, 60_000);
    resolver.cache.lock.lock(common.threadIo()) catch unreachable;
    const v4_lookup = try resolver.cache.cacheLookupOwned(v4_key);
    const v6_lookup = try resolver.cache.cacheLookupOwned(v6_key);
    resolver.cache.lock.unlock(common.threadIo());
    defer switch (v4_lookup) {
        .positive => |owned| std.testing.allocator.free(owned),
        else => {},
    };
    try std.testing.expect(v4_lookup == .positive);
    try std.testing.expect(v6_lookup == .miss);
}

test "DNS negative cache hits are distinct bounded and replacement-safe" {
    var cache = DNSCache.init(std.testing.allocator, .{
        .max_cache_entries = 1,
        .negative_ttl_ms = 60_000,
    });
    defer cache.deinit();

    cache.cacheNegative("one\x00\x00");
    cache.cacheNegative("one\x00\x00");
    try std.testing.expectEqual(@as(u32, 1), cache.count());

    cache.lock.lock(common.threadIo()) catch unreachable;
    const lookup = try cache.cacheLookupOwned("one\x00\x00");
    cache.lock.unlock(common.threadIo());
    try std.testing.expect(lookup == .negative);
    try std.testing.expectEqual(@as(u64, 1), cache.getStats().negative_hits);

    cache.cacheNegative("two\x00\x00");
    try std.testing.expectEqual(@as(u32, 1), cache.count());
}

test "DNS transport failures are preserved and never negative cached" {
    var resolver = DNSResolver.init(std.testing.allocator, .{
        .dns_servers = &.{},
        .cache_enabled = true,
        .dedup_enabled = false,
    });
    defer resolver.deinit();
    try std.testing.expectError(
        error.DnsAllServersFailed,
        resolver.resolve("transport-failure.test", .{}),
    );
    try std.testing.expectEqual(@as(u32, 0), resolver.cache.count());
    try std.testing.expectEqual(@as(u64, 0), resolver.getStats().negative_hits);
}

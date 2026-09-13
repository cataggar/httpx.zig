//! Test-only structural evidence. This does not authorize a CTL extension.
const std = @import("std");
const Reader = @import("x509_policy.zig").Reader;
const Error = @import("trust.zig").TrustError;

pub const Summary = struct {
    pub const max_extensions = 8;
    const State = enum { malformed, unexpected_field, limit, complete };
    const Name = enum { sorted_ctl, next_update_location, crl_next_publish, authority_key_identifier, crl_number, delta_crl, unknown };
    const Shape = enum { empty, binary_or_malformed_der, der, sequence };
    const Detail = struct {
        name: Name = .unknown,
        critical_present: bool = false,
        critical: bool = false,
        value_length: usize = 0,
        shape: Shape = .empty,
        tag: ?u8 = null,
        content_length: usize = 0,
        children: usize = 0,
        child_tags: [8]?u8 = @splat(null),
        children_complete: bool = false,
    };

    state: State = .malformed,
    remaining_length: usize,
    outer_tag: ?u8 = null,
    count: usize = 0,
    details: [max_extensions]Detail = @splat(.{}),

    pub fn inspect(bytes: []const u8, value_limit: usize) Summary {
        var result: Summary = .{ .remaining_length = bytes.len };
        result.parse(bytes, value_limit) catch return result;
        result.state = .complete;
        return result;
    }

    fn parse(self: *Summary, bytes: []const u8, value_limit: usize) Error!void {
        var outer = Reader.init(bytes);
        const wrapper = try outer.any();
        self.outer_tag = wrapper.tag;
        try outer.finish();
        if (wrapper.tag != 0xa0) {
            self.state = .unexpected_field;
            return error.TlsTrustStoreLoadFailed;
        }
        var explicit = Reader.init(wrapper.content);
        var extensions = Reader.init((try explicit.take(0x30)).content);
        try explicit.finish();
        while (extensions.peek() != null) {
            if (self.count == self.details.len) {
                self.state = .limit;
                return error.TlsTrustStoreLoadFailed;
            }
            var extension = Reader.init((try extensions.take(0x30)).content);
            const oid = (try extension.take(0x06)).content;
            if (oid.len == 0 or oid.len > 128) return error.TlsTrustStoreLoadFailed;
            const detail = &self.details[self.count];
            self.count += 1;
            detail.name = name(oid);
            if (extension.peek() == 0x01) {
                const critical = (try extension.take(0x01)).content;
                if (critical.len != 1 or (critical[0] != 0 and critical[0] != 0xff))
                    return error.TlsTrustStoreLoadFailed;
                detail.critical_present = true;
                detail.critical = critical[0] == 0xff;
            }
            const value = (try extension.take(0x04)).content;
            detail.value_length = value.len;
            try extension.finish();
            if (value.len > value_limit) {
                self.state = .limit;
                return error.TlsTrustStoreLoadFailed;
            }
            shape(detail, value);
        }
    }

    fn name(oid: []const u8) Name {
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x01\x01")) return .sorted_ctl;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x02")) return .next_update_location;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x15\x04")) return .crl_next_publish;
        if (std.mem.eql(u8, oid, "\x55\x1d\x23")) return .authority_key_identifier;
        if (std.mem.eql(u8, oid, "\x55\x1d\x14")) return .crl_number;
        if (std.mem.eql(u8, oid, "\x55\x1d\x1b")) return .delta_crl;
        return .unknown;
    }

    fn shape(detail: *Detail, bytes: []const u8) void {
        if (bytes.len == 0) return;
        detail.shape = .binary_or_malformed_der;
        var value = Reader.init(bytes);
        const element = value.any() catch return;
        value.finish() catch return;
        detail.tag = element.tag;
        detail.content_length = element.content.len;
        detail.shape = if (element.tag == 0x30) .sequence else .der;
        if (element.tag != 0x30) return;
        var children = Reader.init(element.content);
        while (children.peek() != null) {
            if (detail.children == detail.child_tags.len) return;
            const child = children.any() catch return;
            detail.child_tags[detail.children] = child.tag;
            detail.children += 1;
        }
        detail.children_complete = true;
    }

    pub fn report(self: Summary, kind: []const u8) void {
        std.debug.print("Windows CTL tail: kind={s} state={s} remaining={d} outer_tag={?d} extensions={d}\n", .{
            kind, @tagName(self.state), self.remaining_length, self.outer_tag, self.count,
        });
        for (self.details[0..self.count], 0..) |detail, index| {
            std.debug.print("CTL extension[{d}]: recognized={s} critical_present={} critical={} value_length={d} shape={s} tag={?d} content_length={d} children={d} complete={} child_tags={any}\n", .{
                index,                                 @tagName(detail.name), detail.critical_present, detail.critical, detail.value_length,
                @tagName(detail.shape),                detail.tag,            detail.content_length,   detail.children, detail.children_complete,
                detail.child_tags[0..detail.children],
            });
        }
    }
};

test "CTL tail summary is bounded structural evidence without payload retention" {
    const sorted = "\x30\x10\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x0a\x01\x01\x04\x02\x30\x00";
    const complete = Summary.inspect("\xa0\x14\x30\x12" ++ sorted, 64);
    try std.testing.expectEqual(Summary.State.complete, complete.state);
    try std.testing.expectEqual(@as(usize, 1), complete.count);
    try std.testing.expectEqual(Summary.Name.sorted_ctl, complete.details[0].name);
    try std.testing.expectEqual(Summary.Shape.sequence, complete.details[0].shape);
    try std.testing.expect(complete.details[0].children_complete);
    try std.testing.expect(!complete.details[0].critical_present);
    try std.testing.expectEqual(Summary.State.limit, Summary.inspect("\xa0\x14\x30\x12" ++ sorted, 1).state);
    try std.testing.expectEqual(Summary.State.unexpected_field, Summary.inspect("\x02\x01\x01", 64).state);
    try std.testing.expectEqual(Summary.State.malformed, Summary.inspect("\xa0\x14\x30\x12" ++ sorted ++ "\x00", 64).state);
    const many = Summary.inspect("\xa0\x81\xa5\x30\x81\xa2" ++ sorted ** 9, 64);
    try std.testing.expectEqual(Summary.State.limit, many.state);
    try std.testing.expectEqual(Summary.max_extensions, many.count);
}

test "CTL tail summary records critical unknown and complete child tag shapes" {
    const extension = "\x30\x12\x06\x03\x2a\x03\x04\x01\x01\xff\x04\x08\x30\x06\x02\x01\x01\x04\x01x";
    const result = Summary.inspect("\xa0\x16\x30\x14" ++ extension, 64);
    try std.testing.expectEqual(Summary.State.complete, result.state);
    try std.testing.expectEqual(Summary.Name.unknown, result.details[0].name);
    try std.testing.expect(result.details[0].critical_present and result.details[0].critical);
    try std.testing.expectEqual(@as(usize, 2), result.details[0].children);
    try std.testing.expectEqual(@as(?u8, 0x02), result.details[0].child_tags[0]);
    try std.testing.expectEqual(@as(?u8, 0x04), result.details[0].child_tags[1]);
}

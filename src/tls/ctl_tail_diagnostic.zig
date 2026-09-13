//! Test-only structural evidence. This does not authorize a CTL extension.
const std = @import("std");
const Reader = @import("x509_policy.zig").Reader;
const Error = @import("trust.zig").TrustError;

pub const Summary = struct {
    pub const max_extensions = 8;
    const State = enum { malformed, unexpected_field, limit, complete };
    const Name = enum {
        sorted_ctl,
        next_update_location,
        crl_next_publish,
        authority_key_identifier,
        crl_number,
        delta_crl,
        sync_root_ctl,
        flight_ctl,
        cert_log_list,
        pin_rules,
        pin_rules_log_end_date,
        hpkp_header_value,
        remove_certificate,
        cross_cert_dist_points,
        certificate_extensions,
        certificate_policies,
        crl_dist_points,
        unknown,
    };
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
        first_fields: usize = 0,
        first_field_tags: [8]?u8 = @splat(null),
        first_field_lengths: [8]usize = @splat(0),
        first_fields_complete: bool = false,
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
        // Public wincrypt.h CTL extension constants; recognizing a name
        // neither validates its value schema nor grants it policy authority.
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x32")) return .sync_root_ctl;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x33")) return .flight_ctl;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x34")) return .cert_log_list;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x21")) return .pin_rules;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x23")) return .pin_rules_log_end_date;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x3d")) return .hpkp_header_value;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x08\x01")) return .remove_certificate;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x0a\x09\x01")) return .cross_cert_dist_points;
        if (std.mem.eql(u8, oid, "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x0e")) return .certificate_extensions;
        if (std.mem.eql(u8, oid, "\x55\x1d\x20")) return .certificate_policies;
        if (std.mem.eql(u8, oid, "\x55\x1d\x1f")) return .crl_dist_points;
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
            if (detail.children == 256) return;
            const child = children.any() catch return;
            if (detail.children < detail.child_tags.len) detail.child_tags[detail.children] = child.tag;
            if (detail.children == 0 and child.tag == 0x30) firstFields(detail, child.content);
            detail.children += 1;
        }
        detail.children_complete = true;
    }

    fn firstFields(detail: *Detail, bytes: []const u8) void {
        var fields = Reader.init(bytes);
        while (fields.peek() != null) {
            if (detail.first_fields == detail.first_field_tags.len) return;
            const field = fields.any() catch return;
            detail.first_field_tags[detail.first_fields] = field.tag;
            detail.first_field_lengths[detail.first_fields] = field.content.len;
            detail.first_fields += 1;
        }
        detail.first_fields_complete = true;
    }

    pub fn report(self: Summary, kind: []const u8) void {
        std.debug.print("Windows CTL tail: kind={s} state={s} remaining={d} outer_tag={?d} extensions={d}\n", .{
            kind, @tagName(self.state), self.remaining_length, self.outer_tag, self.count,
        });
        for (self.details[0..self.count], 0..) |detail, index| {
            std.debug.print("CTL extension[{d}]: recognized={s} critical_present={} critical={} value_length={d} shape={s} tag={?d} content_length={d} children={d} complete={} child_tags={any} first_fields_complete={} first_field_tags={any} first_field_lengths={any}\n", .{
                index,                                                              @tagName(detail.name),        detail.critical_present,                         detail.critical,                                    detail.value_length,
                @tagName(detail.shape),                                             detail.tag,                   detail.content_length,                           detail.children,                                    detail.children_complete,
                detail.child_tags[0..@min(detail.children, detail.child_tags.len)], detail.first_fields_complete, detail.first_field_tags[0..detail.first_fields], detail.first_field_lengths[0..detail.first_fields],
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

test "CTL tail public SDK labels and bounded nested fields imply no authorization" {
    const cases = .{
        .{ "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x32", Summary.Name.sync_root_ctl },
        .{ "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x33", Summary.Name.flight_ctl },
        .{ "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x34", Summary.Name.cert_log_list },
        .{ "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x21", Summary.Name.pin_rules },
        .{ "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x23", Summary.Name.pin_rules_log_end_date },
        .{ "\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x3d", Summary.Name.hpkp_header_value },
        .{ "\x2b\x06\x01\x04\x01\x82\x37\x0a\x08\x01", Summary.Name.remove_certificate },
        .{ "\x2b\x06\x01\x04\x01\x82\x37\x0a\x09\x01", Summary.Name.cross_cert_dist_points },
        .{ "\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x0e", Summary.Name.certificate_extensions },
        .{ "\x55\x1d\x20", Summary.Name.certificate_policies },
        .{ "\x55\x1d\x1f", Summary.Name.crl_dist_points },
    };
    inline for (cases) |case| try std.testing.expectEqual(case[1], Summary.name(case[0]));
    var detail: Summary.Detail = .{};
    Summary.shape(&detail, "\x30\x08\x30\x06\x04\x01x\x0c\x01y");
    try std.testing.expect(detail.children_complete and detail.first_fields_complete);
    try std.testing.expectEqual(@as(usize, 2), detail.first_fields);
    try std.testing.expectEqual(@as(?u8, 0x04), detail.first_field_tags[0]);
    try std.testing.expectEqual(@as(?u8, 0x0c), detail.first_field_tags[1]);
    try std.testing.expectEqual(@as(usize, 1), detail.first_field_lengths[0]);
    var bounded: Summary.Detail = .{};
    Summary.shape(&bounded, "\x30\x82\x02\x02" ++ "\x30\x00" ** 257);
    try std.testing.expectEqual(@as(usize, 256), bounded.children);
    try std.testing.expect(!bounded.children_complete);
}

const std = @import("std");
const p = @import("provider.zig");
const tls = std.crypto.tls;

pub const KeyShare = struct {
    pub const algorithms = [_]p.KeyAgreementAlgorithm{ .x25519, .secp256r1, .secp384r1 };
    keys: [algorithms.len]?p.KeyAgreementKey = .{null} ** algorithms.len,
    public_keys: [algorithms.len][97]u8 = undefined,
    shared_secret: [48]u8 = undefined,
    shared_secret_len: usize = 0,

    pub fn init(provider: p.CryptoProvider, allocator: std.mem.Allocator) p.ProviderError!KeyShare {
        const capabilities = try provider.capabilities();
        var self: KeyShare = .{};
        errdefer self.deinit();
        var count: usize = 0;
        for (algorithms, 0..) |algorithm, i| {
            if (!capabilities.supportsKeyAgreement(algorithm)) continue;
            self.keys[i] = try provider.keyAgreementGenerate(allocator, algorithm);
            try self.keys[i].?.publicKey(self.public_keys[i][0..algorithm.publicKeyLength()]);
            count += 1;
        }
        if (count == 0) return error.UnsupportedAlgorithm;
        return self;
    }

    pub fn publicKey(self: *const KeyShare, group: tls.NamedGroup) ?[]const u8 {
        for (algorithms, 0..) |algorithm, i| {
            if (@intFromEnum(group) == @intFromEnum(algorithm) and self.keys[i] != null)
                return self.public_keys[i][0..algorithm.publicKeyLength()];
        }
        return null;
    }

    pub fn exchange(self: *KeyShare, group: tls.NamedGroup, peer_public_key: []const u8) (p.ProviderError || error{TlsIllegalParameter})!void {
        for (algorithms, 0..) |algorithm, i| {
            if (@intFromEnum(group) != @intFromEnum(algorithm)) continue;
            const key = if (self.keys[i]) |*key| key else return error.TlsIllegalParameter;
            try key.agree(peer_public_key, self.shared_secret[0..algorithm.sharedSecretLength()]);
            self.shared_secret_len = algorithm.sharedSecretLength();
            return;
        }
        return error.TlsIllegalParameter;
    }

    pub fn getSharedSecret(self: *const KeyShare) ?[]const u8 {
        return if (self.shared_secret_len == 0) null else self.shared_secret[0..self.shared_secret_len];
    }

    pub fn deinit(self: *KeyShare) void {
        for (&self.keys) |*key| {
            if (key.*) |*value| value.deinit();
            key.* = null;
        }
        p.secureWipe(&self.shared_secret);
        self.shared_secret_len = 0;
    }
};

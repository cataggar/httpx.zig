//! Opt-in local interoperability probe; see docs/api/tls.md.
//! The production path validator uses explicitly supplied test CA material.
const std = @import("std");
const httpx = @import("httpx");
const p = httpx.crypto_provider;
const tls = httpx.tls;

const ObservedProvider = struct {
    standard: httpx.StandardCryptoProvider,
    selected_aead: p.AeadAlgorithm,
    selected_group: p.KeyAgreementAlgorithm,
    tls12_only: bool = false,
    table: p.VTable,
    calls: struct {
        random: usize = 0,
        hash: usize = 0,
        hmac: usize = 0,
        extract: usize = 0,
        expand: usize = 0,
        prf: usize = 0,
        generate: usize = 0,
        agree: usize = 0,
        verify: usize = 0,
        seal: usize = 0,
        open: usize = 0,
        signing_import: usize = 0,
        sign: usize = 0,
        kem: usize = 0,
        equal: usize = 0,
    } = .{},

    fn init(io: std.Io, allocator: std.mem.Allocator, aead: p.AeadAlgorithm, group: p.KeyAgreementAlgorithm) ObservedProvider {
        var standard = httpx.StandardCryptoProvider.init(io, allocator);
        var table = standard.provider().vtable.*;
        table.capabilities = capabilities;
        table.random = random;
        table.hashCreate = hashCreate;
        table.hmac = hmac;
        table.hkdfExtract = extract;
        table.hkdfExpand = expand;
        table.tls12Prf = prf;
        table.keyAgreementGenerate = generate;
        table.keyAgreementAgree = agree;
        table.verify = verify;
        table.aeadSeal = seal;
        table.aeadOpen = open;
        table.signingKeyImport = signingImport;
        table.sign = sign;
        table.kemEncapsulate = encapsulate;
        table.constantTimeEqual = equal;
        return .{ .standard = standard, .table = table, .selected_aead = aead, .selected_group = group };
    }

    fn provider(self: *ObservedProvider) p.CryptoProvider {
        return p.CryptoProvider.init(&self.standard, &self.table);
    }

    fn owner(context: *anyopaque) *ObservedProvider {
        const standard: *httpx.StandardCryptoProvider = @ptrCast(@alignCast(context));
        return @fieldParentPtr("standard", standard);
    }

    fn capabilities(context: *anyopaque) p.Capabilities {
        const self = owner(context);
        var caps = self.standard.provider().vtable.capabilities(context);
        caps.aeads = 0;
        caps.key_agreements = 0;
        caps.setAead(self.selected_aead, true);
        caps.setKeyAgreement(self.selected_group, true);
        if (self.tls12_only) {
            for (std.enums.values(p.HashAlgorithm)) |hash| caps.setHkdf(hash, false);
        }
        return caps;
    }

    fn random(context: *anyopaque, out: []u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.random += 1;
        return self.standard.provider().vtable.random(context, out);
    }

    fn hashCreate(context: *anyopaque, allocator: std.mem.Allocator, algorithm: p.HashAlgorithm, out: *?*anyopaque) p.ProviderError!void {
        const self = owner(context);
        self.calls.hash += 1;
        return self.standard.provider().vtable.hashCreate(context, allocator, algorithm, out);
    }

    fn hmac(context: *anyopaque, algorithm: p.HashAlgorithm, key: []const u8, parts: []const []const u8, out: []u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.hmac += 1;
        return self.standard.provider().vtable.hmac(context, algorithm, key, parts, out);
    }

    fn extract(context: *anyopaque, algorithm: p.HashAlgorithm, salt: []const u8, parts: []const []const u8, out: []u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.extract += 1;
        return self.standard.provider().vtable.hkdfExtract(context, algorithm, salt, parts, out);
    }

    fn expand(context: *anyopaque, algorithm: p.HashAlgorithm, prk: []const u8, parts: []const []const u8, out: []u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.expand += 1;
        return self.standard.provider().vtable.hkdfExpand(context, algorithm, prk, parts, out);
    }

    fn prf(context: *anyopaque, algorithm: p.HashAlgorithm, secret: []const u8, label: []const u8, seed: []const []const u8, out: []u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.prf += 1;
        return self.standard.provider().vtable.tls12Prf(context, algorithm, secret, label, seed, out);
    }

    fn generate(context: *anyopaque, allocator: std.mem.Allocator, algorithm: p.KeyAgreementAlgorithm, out: *?*anyopaque) p.ProviderError!void {
        const self = owner(context);
        self.calls.generate += 1;
        return self.standard.provider().vtable.keyAgreementGenerate(context, allocator, algorithm, out);
    }

    fn agree(context: *anyopaque, handle: *anyopaque, peer: []const u8, out: []u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.agree += 1;
        return self.standard.provider().vtable.keyAgreementAgree(context, handle, peer, out);
    }

    fn verify(context: *anyopaque, scheme: p.SignatureScheme, key: p.PublicKey, parts: []const []const u8, signature: []const u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.verify += 1;
        return self.standard.provider().vtable.verify(context, scheme, key, parts, signature);
    }

    fn seal(context: *anyopaque, algorithm: p.AeadAlgorithm, key: []const u8, nonce: []const u8, aad: []const []const u8, plaintext: []const u8, ciphertext: []u8, tag: []u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.seal += 1;
        return self.standard.provider().vtable.aeadSeal(context, algorithm, key, nonce, aad, plaintext, ciphertext, tag);
    }

    fn open(context: *anyopaque, algorithm: p.AeadAlgorithm, key: []const u8, nonce: []const u8, aad: []const []const u8, ciphertext: []const u8, tag: []const u8, plaintext: []u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.open += 1;
        return self.standard.provider().vtable.aeadOpen(context, algorithm, key, nonce, aad, ciphertext, tag, plaintext);
    }

    fn signingImport(context: *anyopaque, allocator: std.mem.Allocator, key: p.PrivateKey, out: *?*anyopaque) p.ProviderError!void {
        const self = owner(context);
        self.calls.signing_import += 1;
        return self.standard.provider().vtable.signingKeyImport(context, allocator, key, out);
    }

    fn sign(context: *anyopaque, key: *anyopaque, scheme: p.SignatureScheme, parts: []const []const u8, output: []u8) p.ProviderError!usize {
        const self = owner(context);
        self.calls.sign += 1;
        return self.standard.provider().vtable.sign(context, key, scheme, parts, output);
    }

    fn encapsulate(context: *anyopaque, algorithm: p.KemAlgorithm, key: []const u8, ciphertext: []u8, secret: []u8) p.ProviderError!void {
        const self = owner(context);
        self.calls.kem += 1;
        return self.standard.provider().vtable.kemEncapsulate(context, algorithm, key, ciphertext, secret);
    }

    fn equal(context: *anyopaque, a: []const u8, b: []const u8) p.ProviderError!bool {
        const self = owner(context);
        self.calls.equal += 1;
        return self.standard.provider().vtable.constantTimeEqual(context, a, b);
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);
    if ((args.len == 5 or args.len == 6) and std.mem.eql(u8, args[1], "--connect")) {
        const certificate = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], allocator, .limited(256 * 1024));
        defer allocator.free(certificate);
        var roots = try tls.TrustContext.init(allocator, init.io, .{
            .source = .{ .custom_only = .{ .der_certificates = &.{certificate} } },
            .load_time_seconds = std.Io.Timestamp.now(init.io, .real).toSeconds(),
        });
        defer roots.deinit();
        var observed = ObservedProvider.init(init.io, allocator, .aes_128_gcm, .secp256r1);
        if (args.len == 6) {
            if (!std.mem.eql(u8, args[5], "1.2")) return error.ExpectedTls12;
            observed.tls12_only = true;
        }
        var socket = try httpx.Socket.create();
        defer socket.close();
        try socket.connectWithTimeout(.initIp4(.{ 127, 0, 0, 1 }, try std.fmt.parseInt(u16, args[4], 10)), 5000);
        try socket.setRecvTimeout(5000);
        try socket.setSendTimeout(5000);
        var session = tls.TLSSession.init(.{
            .allocator = allocator,
            .crypto_provider = observed.provider(),
            .server_authentication = .{ .verify = .{ .provider = roots.provider() } },
        });
        defer session.deinit();
        session.attachSocket(&socket);
        try session.handshake(args[3]);
        if (observed.tls12_only and session.tls_version != .tls_1_2) return error.WrongNegotiatedVersion;
        try session.writeAll("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        var response: [1024]u8 = undefined;
        const count = try session.read(&response);
        if (!std.mem.startsWith(u8, response[0..count], "HTTP/1.1 200")) return error.InvalidHttpResponse;
        if (observed.calls.verify < 2 or observed.calls.equal == 0) return error.MissingProviderDispatch;
        std.debug.print("provider client authenticated {s} via {s}\n", .{ args[3], @tagName(session.tls_version.?) });
        return;
    }
    if (args.len == 8 and std.mem.eql(u8, args[1], "--serve")) {
        const port = try std.fmt.parseInt(u16, args[4], 10);
        const aead = std.meta.stringToEnum(p.AeadAlgorithm, args[5]) orelse return error.ExpectedAead;
        const hybrid = std.mem.eql(u8, args[6], "x25519mlkem768");
        const group = if (hybrid) p.KeyAgreementAlgorithm.x25519 else std.meta.stringToEnum(p.KeyAgreementAlgorithm, args[6]) orelse return error.ExpectedGroup;
        const connections = try std.fmt.parseInt(usize, args[7], 10);
        if (connections == 0 or connections > 256) return error.ExpectedConnectionCount;
        var observed = ObservedProvider.init(init.io, allocator, aead, group);
        var config = try tls.loadServerTLSConfigWithProvider(allocator, init.io, args[2], args[3], observed.provider());
        defer config.deinit();
        var listener = try httpx.TcpListener.init(try httpx.Address.parseIp("127.0.0.1", port));
        defer listener.deinit();
        std.debug.print("TLS provider server listening on {d}\n", .{port});
        for (0..connections) |_| {
            var accepted = try listener.accept();
            defer accepted.socket.close();
            try accepted.socket.setRecvTimeout(5000);
            try accepted.socket.setSendTimeout(5000);
            var connection = try tls.acceptServer(allocator, &accepted.socket, &.{ "h2", "http/1.1" }, config);
            defer connection.closeNotify();
            var request: [4096]u8 = undefined;
            const count = try connection.read(&request);
            if (!std.mem.startsWith(u8, request[0..count], "GET ")) return error.InvalidHttpRequest;
            try connection.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
        if (observed.calls.signing_import != 1 or observed.calls.sign != connections + 1 or
            observed.calls.generate != connections or observed.calls.agree != connections or
            observed.calls.equal < connections or observed.calls.seal < 2 * connections or observed.calls.open < 2 * connections or
            observed.calls.hash == 0 or observed.calls.random == 0 or observed.calls.verify == 0)
            return error.MissingProviderDispatch;
        if (hybrid and observed.calls.kem != connections) return error.MissingProviderDispatch;
        std.debug.print("server provider dispatch qualified: {s} {s} ({d} connections)\n", .{ args[5], args[6], connections });
        return;
    }
    if (args.len == 5 and std.mem.eql(u8, args[1], "--sign-rsa")) {
        const algorithm = std.meta.stringToEnum(p.SignatureKeyAlgorithm, args[3]) orelse return error.ExpectedRsaKeyAlgorithm;
        if (algorithm != .rsa and algorithm != .rsa_pss) return error.ExpectedRsaKeyAlgorithm;
        const encoded = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], allocator, .limited(16 * 1024));
        defer {
            p.secureWipe(encoded);
            allocator.free(encoded);
        }
        var standard = httpx.StandardCryptoProvider.init(init.io, allocator);
        var key = try standard.provider().signingKeyImport(allocator, .{
            .algorithm = algorithm,
            .encoding = .pkcs8_der,
            .bytes = encoded,
        });
        defer key.deinit();
        for ([_]p.SignatureScheme{
            .rsa_pkcs1_sha256,    .rsa_pkcs1_sha384,    .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512,
            .rsa_pss_pss_sha256,  .rsa_pss_pss_sha384,  .rsa_pss_pss_sha512,
        }) |scheme| {
            if (scheme.keyAlgorithm() != algorithm) continue;
            var output: [512]u8 = undefined;
            defer p.secureWipe(&output);
            const signature = try key.sign(scheme, &.{"HTTPX RSA provider qualification\n"}, &output);
            const path = try std.fmt.allocPrint(allocator, "{s}/{s}.sig", .{ args[4], @tagName(scheme) });
            defer allocator.free(path);
            try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = path, .data = signature });
        }
        return;
    }
    if (args.len != 4 and args.len != 5) return error.ExpectedCertificateDerAndTls12Tls13Ports;
    const certificate = try std.Io.Dir.cwd().readFileAlloc(init.io, args[1], allocator, .limited(256 * 1024));
    defer allocator.free(certificate);
    const leaf = if (args.len == 5) try std.Io.Dir.cwd().readFileAlloc(init.io, args[4], allocator, .limited(256 * 1024)) else null;
    defer if (leaf) |bytes| allocator.free(bytes);
    const fixture_key = try tls.certificate_crypto.certificatePublicKey(leaf orelse certificate);
    var trust = try tls.TrustContext.init(allocator, init.io, .{
        .source = .{ .custom_only = .{ .der_certificates = &.{certificate} } },
        .load_time_seconds = std.Io.Timestamp.now(init.io, .real).toSeconds(),
    });
    defer trust.deinit();
    const ports = [_]u16{ try std.fmt.parseInt(u16, args[2], 10), try std.fmt.parseInt(u16, args[3], 10) };
    for ([_]std.crypto.tls.ProtocolVersion{ .tls_1_2, .tls_1_3 }, ports) |version, port| {
        for ([_]p.AeadAlgorithm{ .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 }) |aead| {
            for ([_]p.KeyAgreementAlgorithm{ .x25519, .secp256r1, .secp384r1 }) |group| {
                if (version == .tls_1_2) switch (fixture_key.algorithm) {
                    .ecdsa_p256, .ecdsa_p384 => {
                        const required: p.KeyAgreementAlgorithm = if (fixture_key.algorithm == .ecdsa_p256) .secp256r1 else .secp384r1;
                        if (group != required) continue;
                    },
                    else => {},
                };
                var observed = ObservedProvider.init(init.io, allocator, aead, group);
                var socket = try httpx.Socket.create();
                defer socket.close();
                try socket.connectWithTimeout(.initIp4(.{ 127, 0, 0, 1 }, port), 5000);
                try socket.setRecvTimeout(5000);
                try socket.setSendTimeout(5000);
                var session = tls.TLSSession.init(.{
                    .allocator = allocator,
                    .crypto_provider = observed.provider(),
                    .server_authentication = .{ .verify = .{ .provider = trust.provider() } },
                });
                defer session.deinit();
                session.attachSocket(&socket);
                try session.handshake("localhost");
                if (session.tls_version != version) return error.WrongNegotiatedVersion;
                try session.writeAll("GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
                var response: [1024]u8 = undefined;
                const count = try session.read(&response);
                if (!std.mem.startsWith(u8, response[0..count], "HTTP/1.")) return error.InvalidHttpResponse;
                const minimum_verifications: usize = if (leaf != null and !std.mem.eql(u8, leaf.?, certificate)) 2 else 1;
                if (observed.calls.random == 0 or observed.calls.hash == 0 or
                    observed.calls.generate != 1 or observed.calls.agree != 1 or
                    observed.calls.verify < minimum_verifications or observed.calls.seal < 2 or observed.calls.open < 2)
                    return error.MissingProviderDispatch;
                if (version == .tls_1_2 and observed.calls.prf < 4) return error.MissingTls12ProviderPrf;
                if (version == .tls_1_3 and (observed.calls.hmac < 2 or observed.calls.extract < 3 or observed.calls.expand < 10))
                    return error.MissingTls13ProviderKdf;
                std.debug.print("{s} {s} {s}: authenticated handshake + HTTP records OK\n", .{ @tagName(version), @tagName(aead), @tagName(group) });
            }
        }
    }
}

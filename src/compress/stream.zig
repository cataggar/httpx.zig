//! Streaming Compression for httpx.zig
//!
//! Provides chunk-by-chunk compression and decompression without buffering
//! the entire body in memory. Processes data incrementally for large and
//! chunked HTTP responses.
//!
//! Supported encodings:
//!   gzip / deflate  -- stateful incremental flate via std.compress.flate
//!   brotli / zstd   -- native incremental decoders with bounded input/output
//!   identity        -- passthrough
//!
//! The streaming API allows callers to consume decompressed data incrementally
//! without requiring the entire response to exist in memory.
//!
//! Decompression bomb protection: both StreamingDecompressor and
//! StreamingCompressor enforce configurable size limits.

const std = @import("std");
const Allocator = std.mem.Allocator;
const compression = @import("compression.zig");
const ContentEncoding = compression.ContentEncoding;
const brotli = @import("brotli");
const zstd_pkg = @import("zstd");

pub const StreamingError = error{
    DecompressionFailed,
    DecompressionBombDetected,
    CompressionFailed,
    CompressionLimitExceeded,
    IoFailed,
    TruncatedStream,
    MalformedData,
};

pub const StreamingLimits = struct {
    max_decompressed_size: u64 = 100 * 1024 * 1024,
    max_compressed_input: u64 = 256 * 1024 * 1024,
};

pub fn StreamingDecompressor(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        const FlatePipeline = struct {
            source: ReaderType,
            reader_buffer: [16 * 1024]u8 = undefined,
            reader: std.Io.Reader = undefined,
            window_buffer: [std.compress.flate.max_window_len]u8 = undefined,
            decompressor: std.compress.flate.Decompress = undefined,
            source_error: ?anyerror = null,
            source_eof: bool = false,
            compressed_bytes: u64 = 0,
            max_compressed_input: u64,

            fn init(self: *@This(), source: ReaderType, container: std.compress.flate.Container, max_input: u64) void {
                self.* = .{ .source = source, .max_compressed_input = max_input };
                self.reader = .{
                    .vtable = &reader_vtable,
                    .buffer = &self.reader_buffer,
                    .seek = 0,
                    .end = 0,
                };
                self.decompressor = std.compress.flate.Decompress.init(
                    &self.reader,
                    container,
                    &self.window_buffer,
                );
            }

            fn parent(reader: *std.Io.Reader) *@This() {
                return @fieldParentPtr("reader", reader);
            }

            fn readVec(reader: *std.Io.Reader, buffers: [][]u8) std.Io.Reader.Error!usize {
                var vectors: [4][]u8 = undefined;
                const count, const data_size = try reader.writableVector(&vectors, buffers);
                const destinations = vectors[0..count];
                if (destinations.len == 0 or destinations[0].len == 0) return 0;
                const self = parent(reader);
                const n = self.source.readSliceShort(destinations[0]) catch |err| {
                    self.source_error = err;
                    return error.ReadFailed;
                };
                if (n == 0) {
                    self.source_eof = true;
                    return error.EndOfStream;
                }
                self.compressed_bytes = std.math.add(u64, self.compressed_bytes, n) catch {
                    self.source_error = error.DecompressionBombDetected;
                    return error.ReadFailed;
                };
                if (self.max_compressed_input > 0 and
                    self.compressed_bytes > self.max_compressed_input)
                {
                    self.source_error = error.DecompressionBombDetected;
                    return error.ReadFailed;
                }
                if (n > data_size) {
                    reader.end += n - data_size;
                    return data_size;
                }
                return n;
            }

            fn stream(
                reader: *std.Io.Reader,
                writer: *std.Io.Writer,
                limit: std.Io.Limit,
            ) std.Io.Reader.StreamError!usize {
                var total: usize = 0;
                const max = limit.toInt() orelse std.math.maxInt(usize);
                while (total < max) {
                    var output = [_][]u8{reader.buffer[0..@min(reader.buffer.len, max - total)]};
                    const n = readVec(reader, &output) catch |err| switch (err) {
                        error.EndOfStream => break,
                        else => return err,
                    };
                    if (n == 0) break;
                    try writer.writeAll(reader.buffer[0..n]);
                    total += n;
                }
                return total;
            }

            fn discard(reader: *std.Io.Reader, limit: std.Io.Limit) error{ EndOfStream, ReadFailed }!usize {
                var total: usize = 0;
                const max = limit.toInt() orelse std.math.maxInt(usize);
                while (total < max) {
                    var output = [_][]u8{reader.buffer[0..@min(reader.buffer.len, max - total)]};
                    const n = try readVec(reader, &output);
                    if (n == 0) break;
                    total += n;
                }
                return total;
            }

            fn rebase(reader: *std.Io.Reader, _: usize) std.Io.Reader.RebaseError!void {
                const buffered = reader.buffer[reader.seek..reader.end];
                @memmove(reader.buffer[0..buffered.len], buffered);
                reader.seek = 0;
                reader.end = buffered.len;
            }

            const reader_vtable: std.Io.Reader.VTable = .{
                .stream = stream,
                .discard = discard,
                .readVec = readVec,
                .rebase = rebase,
            };
        };

        allocator: Allocator,
        encoding: ContentEncoding,
        reader: ReaderType,
        output_buf: [16 * 1024]u8,
        flate_state: ?*FlatePipeline = null,
        brotli_decoder: ?brotli.Decoder = null,
        zstd_decoder: ?zstd_pkg.StreamingDecompressor = null,
        decoder_input: [16 * 1024]u8 = undefined,
        decoder_input_pos: usize = 0,
        decoder_input_len: usize = 0,
        zstd_output: [128 * 1024]u8 = undefined,
        zstd_output_pos: usize = 0,
        zstd_output_len: usize = 0,
        brotli_finalized: bool = false,
        zstd_finalized: bool = false,
        total_decompressed: u64 = 0,
        total_compressed: u64 = 0,
        limits: StreamingLimits,

        pub fn init(allocator: Allocator, encoding: ContentEncoding, reader: ReaderType) Self {
            return .{
                .allocator = allocator,
                .encoding = encoding,
                .reader = reader,
                .output_buf = undefined,
                .limits = .{},
            };
        }

        pub fn initWithLimits(allocator: Allocator, encoding: ContentEncoding, reader: ReaderType, limits: StreamingLimits) Self {
            return .{
                .allocator = allocator,
                .encoding = encoding,
                .reader = reader,
                .output_buf = undefined,
                .limits = limits,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.flate_state) |pipeline| self.allocator.destroy(pipeline);
            if (self.brotli_decoder) |*decoder| decoder.deinit();
            if (self.zstd_decoder) |*decoder| decoder.deinit();
        }

        pub fn readChunk(self: *Self) !?[]const u8 {
            switch (self.encoding) {
                .identity => {
                    const n = self.reader.readSliceShort(&self.output_buf) catch return error.IoFailed;
                    if (n == 0) return null;
                    self.total_compressed +|= n;
                    if (self.limits.max_compressed_input > 0 and
                        self.total_compressed > self.limits.max_compressed_input)
                    {
                        return error.DecompressionBombDetected;
                    }
                    self.total_decompressed +|= n;
                    if (self.total_decompressed > self.limits.max_decompressed_size) return error.DecompressionBombDetected;
                    return self.output_buf[0..n];
                },
                .gzip, .deflate => return self.readFlateChunk(),
                .br => return self.readBrotliChunk(),
                .zstd => return self.readZstdChunk(),
            }
        }

        // --- Flate (gzip/deflate) streaming ---

        fn ensureFlateInit(self: *Self) !void {
            if (self.flate_state != null) return;
            const container: std.compress.flate.Container = if (self.encoding == .gzip) .gzip else .zlib;
            const pipeline = try self.allocator.create(FlatePipeline);
            pipeline.init(self.reader, container, self.limits.max_compressed_input);
            self.flate_state = pipeline;
        }

        fn readFlateChunk(self: *Self) !?[]const u8 {
            try self.ensureFlateInit();
            const pipeline = self.flate_state.?;
            const n = pipeline.decompressor.reader.readSliceShort(&self.output_buf) catch {
                if (pipeline.source_error) |err| return err;
                return if (pipeline.source_eof) error.TruncatedStream else error.DecompressionFailed;
            };
            self.total_compressed = pipeline.compressed_bytes;
            if (n == 0) return null;
            try self.recordOutput(n);
            return self.output_buf[0..n];
        }

        fn refillDecoderInput(self: *Self) !bool {
            if (self.decoder_input_pos < self.decoder_input_len) return true;
            self.decoder_input_pos = 0;
            self.decoder_input_len = try self.readDecoderBytes(&self.decoder_input);
            return self.decoder_input_len != 0;
        }

        fn readDecoderBytes(self: *Self, output: []u8) !usize {
            const amount = self.reader.readSliceShort(output) catch return error.IoFailed;
            if (amount == 0) return 0;
            self.total_compressed +|= amount;
            if (self.total_compressed > self.limits.max_compressed_input) {
                return error.DecompressionBombDetected;
            }
            return amount;
        }

        fn recordOutput(self: *Self, amount: usize) !void {
            self.total_decompressed +|= amount;
            if (self.total_decompressed > self.limits.max_decompressed_size) {
                return error.DecompressionBombDetected;
            }
        }

        // --- Brotli streaming ---

        fn readBrotliChunk(self: *Self) !?[]const u8 {
            if (self.brotli_finalized) return null;
            if (self.brotli_decoder == null) {
                self.brotli_decoder = brotli.Decoder.init(self.allocator, .{});
            }
            const decoder = &self.brotli_decoder.?;
            var output: []u8 = &self.output_buf;
            while (true) {
                const has_input = try self.refillDecoderInput();
                var input: []const u8 = if (has_input)
                    self.decoder_input[self.decoder_input_pos..self.decoder_input_len]
                else
                    &.{};
                const before = input.len;
                const result = decoder.decompressStream(&input, &output, null);
                self.decoder_input_pos += before - input.len;
                const produced = self.output_buf.len - output.len;
                switch (result) {
                    .success => {
                        if (decoder.br.pos != decoder.br.input.len or decoder.buffer_length != 0) {
                            return error.MalformedData;
                        }
                        self.decoder_input_pos = self.decoder_input_len;
                        var trailing: [1]u8 = undefined;
                        const trailing_len = self.reader.readSliceShort(&trailing) catch
                            return error.IoFailed;
                        if (trailing_len != 0) return error.MalformedData;
                        self.brotli_finalized = true;
                        try self.recordOutput(produced);
                        return if (produced == 0) null else self.output_buf[0..produced];
                    },
                    .needs_more_output => {
                        try self.recordOutput(produced);
                        return self.output_buf[0..produced];
                    },
                    .needs_more_input => {
                        if (produced > 0) {
                            try self.recordOutput(produced);
                            return self.output_buf[0..produced];
                        }
                        if (!has_input) return error.TruncatedStream;
                    },
                    .err => return switch (decoder.errorCode()) {
                        .alloc_context_modes,
                        .alloc_tree_groups,
                        .alloc_context_map,
                        .alloc_ring_buffer_1,
                        .alloc_ring_buffer_2,
                        .alloc_block_type_trees,
                        => error.OutOfMemory,
                        else => error.DecompressionFailed,
                    },
                }
            }
        }

        // --- Zstd streaming ---

        fn readZstdChunk(self: *Self) !?[]const u8 {
            if (self.zstd_finalized) return null;
            if (self.zstd_decoder == null) {
                self.zstd_decoder = zstd_pkg.StreamingDecompressor.init(self.allocator);
            }
            if (self.zstd_output_pos < self.zstd_output_len) {
                const amount = @min(self.output_buf.len, self.zstd_output_len - self.zstd_output_pos);
                @memcpy(self.output_buf[0..amount], self.zstd_output[self.zstd_output_pos..][0..amount]);
                self.zstd_output_pos += amount;
                try self.recordOutput(amount);
                return self.output_buf[0..amount];
            }
            const decoder = &self.zstd_decoder.?;
            while (true) {
                const has_input = try self.refillDecoderInput();
                const input = if (has_input)
                    self.decoder_input[self.decoder_input_pos..self.decoder_input_len]
                else
                    &.{};
                const result = try decoder.decompressStream(&self.zstd_output, input);
                self.decoder_input_pos += result.in_consumed;
                if (decoder.frame_header) |frame_header| {
                    const window = std.math.cast(usize, frame_header.window_size) orelse
                        return error.DecompressionBombDetected;
                    if (@as(u64, window) > self.limits.max_decompressed_size) {
                        return error.DecompressionBombDetected;
                    }
                    if (decoder.out_buffer.items.len > window) {
                        const retained = decoder.out_buffer.items[decoder.out_buffer.items.len - window ..];
                        @memmove(decoder.out_buffer.items[0..window], retained);
                        decoder.out_buffer.shrinkRetainingCapacity(window);
                    }
                }
                if (result.out_produced > 0) {
                    self.zstd_output_pos = 0;
                    self.zstd_output_len = result.out_produced;
                    const amount = @min(self.output_buf.len, result.out_produced);
                    @memcpy(self.output_buf[0..amount], self.zstd_output[0..amount]);
                    self.zstd_output_pos = amount;
                    try self.recordOutput(amount);
                    return self.output_buf[0..amount];
                }
                if (!has_input) {
                    if (self.total_compressed == 0) return error.TruncatedStream;
                    if (result.needs_more) return error.TruncatedStream;
                    self.zstd_finalized = true;
                    return null;
                }
                if (result.in_consumed == 0) return error.DecompressionFailed;
            }
        }
    };
}

pub const StreamingCompressor = struct {
    allocator: Allocator,
    encoding: ContentEncoding,
    aw: std.Io.Writer.Allocating,
    flate_compressor: ?flate_comp_state = null,
    brotli_compressor: ?brotli.StreamingCompressor = null,
    window_buf: [std.compress.flate.max_window_len]u8,
    total_input: usize = 0,
    limits: StreamingLimits,
    level: compression.CompressionLevel,

    const flate_comp_state = struct {
        compressor: std.compress.flate.Compress,
    };

    pub fn init(allocator: Allocator, encoding: ContentEncoding) StreamingCompressor {
        return .{
            .allocator = allocator,
            .encoding = encoding,
            .aw = .init(allocator),
            .flate_compressor = null,
            .brotli_compressor = null,
            .window_buf = undefined,
            .limits = .{},
            .level = .default,
        };
    }

    pub fn initWithOptions(allocator: Allocator, encoding: ContentEncoding, level: compression.CompressionLevel, limits: StreamingLimits) StreamingCompressor {
        return .{
            .allocator = allocator,
            .encoding = encoding,
            .aw = .init(allocator),
            .flate_compressor = null,
            .brotli_compressor = null,
            .window_buf = undefined,
            .limits = limits,
            .level = level,
        };
    }

    pub fn deinit(self: *StreamingCompressor) void {
        if (self.brotli_compressor) |*bc| bc.deinit();
        self.brotli_compressor = null;
        self.aw.deinit();
    }

    pub fn start(self: *StreamingCompressor) !void {
        switch (self.encoding) {
            .identity => {},
            .gzip, .deflate => {
                self.aw.ensureUnusedCapacity(256) catch return error.CompressionFailed;
                const container: std.compress.flate.Container = if (self.encoding == .gzip) .gzip else .zlib;
                const flate_level = switch (self.level) {
                    .fast => std.compress.flate.Compress.Options.level_1,
                    .default => std.compress.flate.Compress.Options.level_6,
                    .best => std.compress.flate.Compress.Options.level_9,
                };
                const compressor = std.compress.flate.Compress.init(
                    &self.aw.writer,
                    &self.window_buf,
                    container,
                    flate_level,
                ) catch return error.CompressionFailed;
                self.flate_compressor = .{ .compressor = compressor };
            },
            .br => {
                // Use the brotli package's incremental encoder so all chunks form
                // ONE continuous stream (concatenated one-shot streams cannot be
                // decoded because brotli has no per-stream magic number).
                const quality: u32 = switch (self.level) {
                    .fast => 4,
                    .default => 9,
                    .best => 11,
                };
                self.brotli_compressor = brotli.StreamingCompressor.init(self.allocator, .{
                    .quality = quality,
                    .lgwin = 22,
                });
            },
            .zstd => {},
        }
    }

    pub fn writeChunk(self: *StreamingCompressor, chunk: []const u8) !void {
        if (chunk.len == 0) return;

        self.total_input +|= chunk.len;
        if (self.total_input > self.limits.max_compressed_input) return error.CompressionLimitExceeded;

        switch (self.encoding) {
            .identity => {
                _ = self.aw.writer.writeAll(chunk) catch return error.IoFailed;
            },
            .gzip, .deflate => {
                if (self.flate_compressor) |*state| {
                    _ = state.compressor.writer.writeAll(chunk) catch return error.CompressionFailed;
                } else {
                    return error.CompressionFailed;
                }
            },
            .br => {
                if (self.brotli_compressor) |*bc| {
                    const piece = bc.process(chunk) catch return error.CompressionFailed;
                    defer self.allocator.free(piece);
                    _ = self.aw.writer.writeAll(piece) catch return error.IoFailed;
                } else {
                    return error.CompressionFailed;
                }
            },
            .zstd => {
                const zstd_level: i32 = switch (self.level) {
                    .fast => 1,
                    .default => 3,
                    .best => 19,
                };
                const compressed = zstd_pkg.compressWithLevel(self.allocator, chunk, zstd_level) catch return error.CompressionFailed;
                defer self.allocator.free(compressed);
                _ = self.aw.writer.writeAll(compressed) catch return error.IoFailed;
            },
        }
    }

    pub fn finish(self: *StreamingCompressor) !void {
        switch (self.encoding) {
            .identity => {},
            .gzip, .deflate => {
                if (self.flate_compressor) |*state| {
                    state.compressor.finish() catch return error.CompressionFailed;
                    self.flate_compressor = null;
                }
            },
            .br => {
                if (self.brotli_compressor) |*bc| {
                    const tail = bc.finish() catch return error.CompressionFailed;
                    defer self.allocator.free(tail);
                    _ = self.aw.writer.writeAll(tail) catch return error.IoFailed;
                    bc.deinit();
                    self.brotli_compressor = null;
                }
            },
            .zstd => {},
        }
    }

    pub fn getWritten(self: *const StreamingCompressor) []const u8 {
        return self.aw.getWritten();
    }

    pub fn toOwnedSlice(self: *StreamingCompressor) ![]u8 {
        return self.aw.toOwnedSlice();
    }
};

test "streaming decompressor gzip round trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const sample = "Hello, streaming decompression test with gzip encoding!";
    const compressed = try compression.compress(allocator, .gzip, sample);
    defer allocator.free(compressed);

    const r: std.Io.Reader = .fixed(compressed);
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .gzip, r);
    defer decompressor.deinit();

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    while (try decompressor.readChunk()) |chunk| {
        try result.appendSlice(allocator, chunk);
    }

    try testing.expectEqualStrings(sample, result.items);
}

test "streaming flate decoder preserves incremental state and propagates failures" {
    const allocator = std.testing.allocator;
    const input = try allocator.alloc(u8, 256 * 1024);
    defer allocator.free(input);
    var random_state: u64 = 0xa0761d6478bd642f;
    for (input) |*byte| {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 7;
        random_state ^= random_state << 17;
        byte.* = @truncate(random_state);
    }
    const compressed = try compression.compress(allocator, .gzip, input);
    defer allocator.free(compressed);

    const ChunkReader = struct {
        data: []const u8,
        offset: usize = 0,
        max_chunk: usize,
        fail_after: ?usize = null,

        pub fn readSliceShort(self: *@This(), output: []u8) !usize {
            if (self.fail_after) |limit| {
                if (self.offset >= limit) return error.SourceReadFailure;
            }
            if (self.offset == self.data.len) return 0;
            const amount = @min(output.len, self.max_chunk, self.data.len - self.offset);
            @memcpy(output[0..amount], self.data[self.offset..][0..amount]);
            self.offset += amount;
            return amount;
        }
    };

    var reader = ChunkReader{ .data = compressed, .max_chunk = 37 };
    var decoder = StreamingDecompressor(*ChunkReader).initWithLimits(
        allocator,
        .gzip,
        &reader,
        .{
            .max_decompressed_size = input.len,
            .max_compressed_input = compressed.len,
        },
    );
    defer decoder.deinit();
    var offset: usize = 0;
    while (try decoder.readChunk()) |chunk| {
        try std.testing.expectEqualSlices(u8, input[offset..][0..chunk.len], chunk);
        offset += chunk.len;
    }
    try std.testing.expectEqual(input.len, offset);

    var truncated_reader = ChunkReader{
        .data = compressed[0 .. compressed.len - 3],
        .max_chunk = 29,
    };
    var truncated = StreamingDecompressor(*ChunkReader).init(
        allocator,
        .gzip,
        &truncated_reader,
    );
    defer truncated.deinit();
    while (true) {
        if (truncated.readChunk()) |chunk| {
            if (chunk == null) return error.TestUnexpectedResult;
        } else |err| {
            try std.testing.expectEqual(error.TruncatedStream, err);
            break;
        }
    }

    var limited_reader = ChunkReader{ .data = compressed, .max_chunk = 31 };
    var limited = StreamingDecompressor(*ChunkReader).initWithLimits(
        allocator,
        .gzip,
        &limited_reader,
        .{ .max_compressed_input = compressed.len - 1 },
    );
    defer limited.deinit();
    while (true) {
        if (limited.readChunk()) |chunk| {
            if (chunk == null) return error.TestUnexpectedResult;
        } else |err| {
            try std.testing.expectEqual(error.DecompressionBombDetected, err);
            break;
        }
    }

    var failing_reader = ChunkReader{
        .data = compressed,
        .max_chunk = 7,
        .fail_after = 7,
    };
    var failing = StreamingDecompressor(*ChunkReader).init(
        allocator,
        .gzip,
        &failing_reader,
    );
    defer failing.deinit();
    while (true) {
        if (failing.readChunk()) |chunk| {
            if (chunk == null) return error.TestUnexpectedResult;
        } else |err| {
            try std.testing.expectEqual(error.SourceReadFailure, err);
            break;
        }
    }
}

test "streaming flate pipeline is allocation failure safe" {
    const compressed = try compression.compress(
        std.testing.allocator,
        .gzip,
        "allocation-safe incremental gzip",
    );
    defer std.testing.allocator.free(compressed);
    const Case = struct {
        fn run(allocator: Allocator, wire: []const u8) !void {
            const reader: std.Io.Reader = .fixed(wire);
            var decoder = StreamingDecompressor(std.Io.Reader).init(
                allocator,
                .gzip,
                reader,
            );
            defer decoder.deinit();
            var total: usize = 0;
            while (try decoder.readChunk()) |chunk| total += chunk.len;
            try std.testing.expect(total > 0);
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Case.run,
        .{compressed},
    );
}

test "streaming decompressor deflate round trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const sample = "Hello, streaming decompression test with deflate encoding!";
    const compressed = try compression.compress(allocator, .deflate, sample);
    defer allocator.free(compressed);

    const r: std.Io.Reader = .fixed(compressed);
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .deflate, r);
    defer decompressor.deinit();

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    while (try decompressor.readChunk()) |chunk| {
        try result.appendSlice(allocator, chunk);
    }

    try testing.expectEqualStrings(sample, result.items);
}

test "streaming decompressor brotli round trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const sample = "Hello, streaming decompression test with brotli encoding! This is a longer string to test accumulation.";
    const compressed = try compression.compress(allocator, .br, sample);
    defer allocator.free(compressed);

    const r: std.Io.Reader = .fixed(compressed);
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .br, r);
    defer decompressor.deinit();

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    while (try decompressor.readChunk()) |chunk| {
        try result.appendSlice(allocator, chunk);
    }

    try testing.expectEqualStrings(sample, result.items);
}

test "streaming decompressor zstd round trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const sample = "Hello, streaming decompression test with zstd encoding! Another longer string.";
    const compressed = try compression.compress(allocator, .zstd, sample);
    defer allocator.free(compressed);

    const r: std.Io.Reader = .fixed(compressed);
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .zstd, r);
    defer decompressor.deinit();

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    while (try decompressor.readChunk()) |chunk| {
        try result.appendSlice(allocator, chunk);
    }

    try testing.expectEqualStrings(sample, result.items);
}

test "streaming zstd decoder keeps large output incremental" {
    const allocator = std.testing.allocator;
    const input = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(input);
    var random_state: u64 = 0xd1b54a32d192ed03;
    for (input) |*byte| {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 7;
        random_state ^= random_state << 17;
        byte.* = @truncate(random_state);
    }
    const compressed = try compression.compress(allocator, .zstd, input);
    defer allocator.free(compressed);

    const reader: std.Io.Reader = .fixed(compressed);
    var decoder = StreamingDecompressor(std.Io.Reader).initWithLimits(
        allocator,
        .zstd,
        reader,
        .{
            .max_decompressed_size = input.len,
            .max_compressed_input = compressed.len,
        },
    );
    defer decoder.deinit();
    var offset: usize = 0;
    while (try decoder.readChunk()) |chunk| {
        try std.testing.expectEqualSlices(u8, input[offset..][0..chunk.len], chunk);
        offset += chunk.len;
    }
    try std.testing.expectEqual(input.len, offset);
}

test "streaming decompressor identity" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const sample = "Uncompressed identity data";
    const r: std.Io.Reader = .fixed(sample);
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .identity, r);
    defer decompressor.deinit();

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    while (try decompressor.readChunk()) |chunk| {
        try result.appendSlice(allocator, chunk);
    }

    try testing.expectEqualStrings(sample, result.items);
}

test "streaming compressor gzip round trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var compressor = StreamingCompressor.init(allocator, .gzip);
    defer compressor.deinit();
    try compressor.start();

    try compressor.writeChunk("Hello, ");
    try compressor.writeChunk("streaming ");
    try compressor.writeChunk("compression!");
    try compressor.finish();

    const compressed = try compressor.toOwnedSlice();
    defer allocator.free(compressed);

    try testing.expect(compressed.len > 0);

    const r: std.Io.Reader = .fixed(compressed);
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .gzip, r);
    defer decompressor.deinit();

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    while (try decompressor.readChunk()) |chunk| {
        try result.appendSlice(allocator, chunk);
    }

    try testing.expectEqualStrings("Hello, streaming compression!", result.items);
}

test "streaming compressor deflate round trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var compressor = StreamingCompressor.init(allocator, .deflate);
    defer compressor.deinit();
    try compressor.start();

    try compressor.writeChunk("Deflate streaming test data");
    try compressor.finish();

    const compressed = try compressor.toOwnedSlice();
    defer allocator.free(compressed);

    try testing.expect(compressed.len > 0);

    const r: std.Io.Reader = .fixed(compressed);
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .deflate, r);
    defer decompressor.deinit();

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    while (try decompressor.readChunk()) |chunk| {
        try result.appendSlice(allocator, chunk);
    }

    try testing.expectEqualStrings("Deflate streaming test data", result.items);
}

test "streaming compressor brotli round trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var compressor = StreamingCompressor.init(allocator, .br);
    defer compressor.deinit();
    try compressor.start();

    try compressor.writeChunk("Brotli ");
    try compressor.writeChunk("streaming ");
    try compressor.writeChunk("compression test!");
    try compressor.finish();

    const compressed = try compressor.toOwnedSlice();
    defer allocator.free(compressed);

    try testing.expect(compressed.len > 0);

    const r: std.Io.Reader = .fixed(compressed);
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .br, r);
    defer decompressor.deinit();

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    while (try decompressor.readChunk()) |chunk| {
        try result.appendSlice(allocator, chunk);
    }

    try testing.expectEqualStrings("Brotli streaming compression test!", result.items);
}

test "streaming compressor zstd multi-chunk round trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var compressor = StreamingCompressor.init(allocator, .zstd);
    defer compressor.deinit();
    try compressor.start();

    // Multiple chunks produce independent zstd frames; the decompressor
    // must handle the concatenated frame stream.
    try compressor.writeChunk("Zstd chunk one. ");
    try compressor.writeChunk("Zstd chunk two. ");
    try compressor.writeChunk("Zstd chunk three.");
    try compressor.finish();

    const compressed = try compressor.toOwnedSlice();
    defer allocator.free(compressed);

    try testing.expect(compressed.len > 0);

    const r: std.Io.Reader = .fixed(compressed);
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .zstd, r);
    defer decompressor.deinit();

    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    while (try decompressor.readChunk()) |chunk| {
        try result.appendSlice(allocator, chunk);
    }

    try testing.expectEqualStrings("Zstd chunk one. Zstd chunk two. Zstd chunk three.", result.items);
}

test "streaming decompressor bomb protection" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const sample = "Bomb test data";
    const compressed = try compression.compress(allocator, .gzip, sample);
    defer allocator.free(compressed);

    const r: std.Io.Reader = .fixed(compressed);
    var decompressor = StreamingDecompressor(std.Io.Reader).initWithLimits(allocator, .gzip, r, .{
        .max_decompressed_size = 5,
    });
    defer decompressor.deinit();

    const result = decompressor.readChunk();
    try testing.expectError(error.DecompressionBombDetected, result);
}

test "streaming decompressor empty input" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const r: std.Io.Reader = .fixed("");
    var decompressor = StreamingDecompressor(std.Io.Reader).init(allocator, .gzip, r);
    defer decompressor.deinit();

    const result = decompressor.readChunk();
    try testing.expectError(error.TruncatedStream, result);

    const zstd_reader: std.Io.Reader = .fixed("");
    var zstd = StreamingDecompressor(std.Io.Reader).init(
        allocator,
        .zstd,
        zstd_reader,
    );
    defer zstd.deinit();
    try testing.expectError(error.TruncatedStream, zstd.readChunk());
}

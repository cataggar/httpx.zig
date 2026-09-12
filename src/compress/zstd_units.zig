const std = @import("std");
const zstd = @import("zstd");

/// Feed at most one frame header, block, or checksum to the codec at a time.
/// A codec call can then produce no more than one 128 KiB block.
pub const Framer = struct {
    stage: enum { frame_header, block, checksum } = .frame_header,
    frame_checksum: bool = false,
    frames_completed: u64 = 0,

    pub const Unit = union(enum) {
        need: usize,
        bytes: usize,
    };

    pub fn next(self: *Framer, input: []const u8, max_window_size: u64) !Unit {
        switch (self.stage) {
            .frame_header => {
                if (input.len < 5) return .{ .need = 5 };
                if (std.mem.readInt(u32, input[0..4], .little) != zstd.MAGICNUMBER) {
                    return error.DecompressionFailed;
                }
                const descriptor = input[4];
                const single_segment = ((descriptor >> 5) & 1) != 0;
                const dictionary_sizes = [_]usize{ 0, 1, 2, 4 };
                const content_sizes = [_]usize{ 0, 2, 4, 8 };
                var size: usize = 5;
                if (!single_segment) size += 1;
                size += dictionary_sizes[descriptor & 0x03];
                const content_code: u2 = @truncate(descriptor >> 6);
                size += if (content_code == 0 and single_segment) 1 else content_sizes[content_code];
                if (input.len < size) return .{ .need = size };
                const header = zstd.getFrameHeader(input[0..size]) catch return error.DecompressionFailed;
                if (header.window_size > max_window_size or header.window_size > std.math.maxInt(usize)) {
                    return error.DecompressionWindowTooLarge;
                }
                self.frame_checksum = header.checksum_flag;
                self.stage = .block;
                return .{ .bytes = size };
            },
            .block => {
                if (input.len < 3) return .{ .need = 3 };
                const raw = @as(u32, input[0]) | (@as(u32, input[1]) << 8) | (@as(u32, input[2]) << 16);
                const encoded_size: usize = @intCast(raw >> 3);
                if (encoded_size > zstd.BLOCKSIZE_MAX) return error.DecompressionFailed;
                const block_type: zstd.BlockType = @enumFromInt((raw >> 1) & 0x03);
                const payload_size = switch (block_type) {
                    .raw, .compressed => encoded_size,
                    .rle => 1,
                    .reserved => return error.DecompressionFailed,
                };
                const size = 3 + payload_size;
                if (input.len < size) return .{ .need = size };
                if ((raw & 1) != 0) {
                    if (self.frame_checksum) {
                        self.stage = .checksum;
                    } else {
                        try self.finishFrame();
                    }
                }
                return .{ .bytes = size };
            },
            .checksum => {
                if (input.len < 4) return .{ .need = 4 };
                try self.finishFrame();
                return .{ .bytes = 4 };
            },
        }
    }

    fn finishFrame(self: *Framer) !void {
        self.frames_completed = std.math.add(u64, self.frames_completed, 1) catch return error.DecompressionFailed;
        self.stage = .frame_header;
    }
};

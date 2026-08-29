const std = @import("std");
const httpx = @import("httpx");

const Loopback = struct {
    listener: *httpx.TcpListener,
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.failure = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var accepted = try self.listener.accept();
        defer accepted.socket.close();

        var request: [4096]u8 = undefined;
        var length: usize = 0;
        while (std.mem.indexOf(u8, request[0..length], "\r\n\r\n") == null) {
            const n = try accepted.socket.read(request[length..]);
            if (n == 0) return error.UnexpectedEndOfStream;
            length += n;
        }
        try accepted.socket.writeAll("HTTP/1.1 100 Continue\r\n\r\n");
        while (std.mem.indexOf(u8, request[0..length], "0\r\n\r\n") == null) {
            const n = try accepted.socket.read(request[length..]);
            if (n == 0) return error.UnexpectedEndOfStream;
            length += n;
        }

        try accepted.socket.writeAll(
            "HTTP/1.1 200 OK\r\n" ++
                "Transfer-Encoding: chunked\r\n" ++
                "Connection: close\r\n\r\n" ++
                "7\r\nstream-\r\n" ++
                "2\r\nok\r\n" ++
                "0\r\n\r\n",
        );
    }
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var listener = try httpx.TcpListener.init(try httpx.Address.parseIp("127.0.0.1", 0));
    defer listener.deinit();
    const address = try listener.getLocalAddress();

    var loopback = Loopback{ .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Loopback.run, .{&loopback});
    var joined = false;
    defer if (!joined) {
        listener.deinit();
        thread.join();
    };

    const url = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/upload",
        .{address.getPort()},
    );
    defer allocator.free(url);

    var client = httpx.Client.initWithConfig(allocator, .{
        .keep_alive = false,
        .timeouts = httpx.Timeouts.uniform(5_000),
    });
    defer client.deinit();

    var operation = try client.open(.POST, url, .{
        .body_mode = .chunked,
        .expect_100_continue = true,
    });
    defer operation.deinit();

    if (try operation.waitForContinue() != .send_body) return error.UploadRejected;
    try operation.writeAll("hello ");
    try operation.writeAll("stream");

    const response = try operation.finishRequest(null);
    std.debug.print("status: {d}\n", .{response.status.code});

    var buffer: [16 * 1024]u8 = undefined;
    while (true) {
        const n = try operation.read(&buffer);
        if (n == 0) break;
        std.debug.print("{s}", .{buffer[0..n]});
    }
    std.debug.print("\n", .{});
    try operation.finish(.{});

    thread.join();
    joined = true;
    if (loopback.failure) |err| return err;
}

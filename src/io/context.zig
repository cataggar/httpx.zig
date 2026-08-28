//! Cancellation and monotonic deadline state shared by blocking I/O phases.
//!
//! An `IoContext` owns its operation-local cancellation token and optionally
//! borrows an external token. The caller must keep the external token alive for
//! the context's lifetime. `cancel()` only signals the local token.
//!
//! `cancel()`, `isCancelled()`, and `check()` are thread-safe. Deadline setters
//! are owner-thread operations and must not race I/O or cancellation checks.

const std = @import("std");
const types = @import("../core/types.zig");
const io_util = @import("any_io.zig");

pub const max_wait_slice_ns: u64 = 10 * std.time.ns_per_ms;

pub const Deadline = struct {
    at_ns: u64,

    pub fn at(at_ns: u64) Deadline {
        return .{ .at_ns = at_ns };
    }

    pub fn afterNsAt(now_ns: u64, duration_ns: u64) Deadline {
        return .{ .at_ns = now_ns +| duration_ns };
    }

    pub fn afterMsAt(now_ns: u64, duration_ms: u64) Deadline {
        return afterNsAt(now_ns, millisecondsToNanoseconds(duration_ms));
    }

    pub fn afterMs(duration_ms: u64) Deadline {
        return afterMsAt(monotonicNowNs(), duration_ms);
    }

    pub fn remainingNsAt(self: Deadline, now_ns: u64) u64 {
        return self.at_ns -| now_ns;
    }

    pub fn isExpiredAt(self: Deadline, now_ns: u64) bool {
        return now_ns >= self.at_ns;
    }
};

pub const DeadlineSource = enum {
    request,
    phase,
};

pub const SelectedDeadline = struct {
    deadline: Deadline,
    source: DeadlineSource,
};

pub const Error = error{
    Cancelled,
    Timeout,
};

/// Combines borrowed external cancellation, owned local cancellation, and
/// optional request/phase deadlines measured against a monotonic clock.
///
/// Cancellation deterministically takes precedence over timeout. The earliest
/// deadline wins; a request deadline wins an exact tie with a phase deadline.
pub const IoContext = struct {
    external_cancel: ?*const types.CancellationToken = null,
    local_cancel: types.CancellationToken = .{},
    request_deadline: ?Deadline = null,
    phase_deadline: ?Deadline = null,

    const Self = @This();

    pub const Options = struct {
        external_cancel: ?*const types.CancellationToken = null,
        request_deadline: ?Deadline = null,
        phase_deadline: ?Deadline = null,
    };

    pub fn init(options: Options) Self {
        return .{
            .external_cancel = options.external_cancel,
            .request_deadline = options.request_deadline,
            .phase_deadline = options.phase_deadline,
        };
    }

    /// Signals only this context's operation-local token.
    pub fn cancel(self: *Self) void {
        self.local_cancel.cancel();
    }

    pub fn isLocallyCancelled(self: *const Self) bool {
        return self.local_cancel.isCancelled();
    }

    pub fn isCancelled(self: *const Self) bool {
        if (self.local_cancel.isCancelled()) return true;
        if (self.external_cancel) |token| return token.isCancelled();
        return false;
    }

    /// Sets a phase deadline. The owner thread may update this between phases.
    pub fn setPhaseDeadline(self: *Self, deadline: ?Deadline) void {
        self.phase_deadline = deadline;
    }

    /// Sets a phase timeout relative to the current monotonic time.
    /// A timeout of zero creates an immediate deadline.
    pub fn setPhaseTimeoutMs(self: *Self, timeout_ms: u64) void {
        self.phase_deadline = Deadline.afterMs(timeout_ms);
    }

    pub fn selectedDeadline(self: *const Self) ?SelectedDeadline {
        if (self.request_deadline) |request| {
            if (self.phase_deadline) |phase| {
                if (request.at_ns <= phase.at_ns) {
                    return .{ .deadline = request, .source = .request };
                }
                return .{ .deadline = phase, .source = .phase };
            }
            return .{ .deadline = request, .source = .request };
        }
        if (self.phase_deadline) |phase| {
            return .{ .deadline = phase, .source = .phase };
        }
        return null;
    }

    pub fn remainingNsAt(self: *const Self, now_ns: u64) ?u64 {
        const selected = self.selectedDeadline() orelse return null;
        return selected.deadline.remainingNsAt(now_ns);
    }

    pub fn remainingNs(self: *const Self) ?u64 {
        return self.remainingNsAt(monotonicNowNs());
    }

    pub fn expiredDeadlineAt(self: *const Self, now_ns: u64) ?DeadlineSource {
        const selected = self.selectedDeadline() orelse return null;
        if (!selected.deadline.isExpiredAt(now_ns)) return null;
        return selected.source;
    }

    pub fn expiredDeadline(self: *const Self) ?DeadlineSource {
        return self.expiredDeadlineAt(monotonicNowNs());
    }

    pub fn checkAt(self: *const Self, now_ns: u64) Error!void {
        if (self.isCancelled()) return error.Cancelled;
        if (self.expiredDeadlineAt(now_ns) != null) return error.Timeout;
    }

    pub fn check(self: *const Self) Error!void {
        return self.checkAt(monotonicNowNs());
    }

    /// Checks cancellation/deadlines before unwrapping a completed blocking
    /// operation. Evaluate and capture `result` before calling this helper so a
    /// cancellation or deadline that becomes active while the operation blocks
    /// deterministically takes precedence over the operation's own error.
    pub fn unwrapAfterBlocking(
        self: *const Self,
        comptime T: type,
        result: anyerror!T,
    ) anyerror!T {
        try self.check();
        return try result;
    }

    /// Sleeps for up to `duration_ms`, waking in bounded slices to observe
    /// cancellation and deadlines. Context deadline expiry returns
    /// `error.Timeout`; completing the requested delay returns success.
    pub fn waitForMs(self: *const Self, duration_ms: u64) Error!void {
        return self.waitForNs(millisecondsToNanoseconds(duration_ms));
    }

    pub fn waitForNs(self: *const Self, duration_ns: u64) Error!void {
        var clock = SystemClock{};
        return self.waitForNsWithClock(duration_ns, &clock);
    }

    fn waitForNsWithClock(self: *const Self, duration_ns: u64, clock: anytype) Error!void {
        const started_ns = clock.nowNs();
        const wait_deadline_ns = started_ns +| duration_ns;
        var now_ns = started_ns;

        while (true) {
            try self.checkAt(now_ns);
            if (now_ns >= wait_deadline_ns) return;

            var sleep_ns = @min(wait_deadline_ns - now_ns, max_wait_slice_ns);
            if (self.remainingNsAt(now_ns)) |remaining_ns| {
                sleep_ns = @min(sleep_ns, remaining_ns);
            }

            if (sleep_ns == 0) return error.Timeout;
            try clock.sleepNs(sleep_ns);
            now_ns = clock.nowNs();
        }
    }
};

pub fn millisecondsToNanoseconds(milliseconds: u64) u64 {
    return std.math.mul(u64, milliseconds, std.time.ns_per_ms) catch std.math.maxInt(u64);
}

pub fn monotonicNowNs() u64 {
    const raw = std.Io.Timestamp.now(io_util.threadIo(), .awake).toNanoseconds();
    if (raw <= 0) return 0;
    return @intCast(@min(raw, @as(i96, std.math.maxInt(u64))));
}

const SystemClock = struct {
    fn nowNs(_: *@This()) u64 {
        return monotonicNowNs();
    }

    fn sleepNs(_: *@This(), duration_ns: u64) Error!void {
        const duration = std.Io.Duration.fromNanoseconds(@intCast(duration_ns));
        std.Io.sleep(io_util.threadIo(), duration, .awake) catch |err| switch (err) {
            error.Canceled => return error.Cancelled,
        };
    }
};

const FakeClock = struct {
    now_ns: u64 = 0,
    sleep_calls: usize = 0,
    smallest_sleep_ns: u64 = std.math.maxInt(u64),
    cancel_on_first_sleep: ?*IoContext = null,
    zero_progress_sleeps: usize = 0,

    fn nowNs(self: *@This()) u64 {
        return self.now_ns;
    }

    fn sleepNs(self: *@This(), duration_ns: u64) Error!void {
        self.sleep_calls += 1;
        self.smallest_sleep_ns = @min(self.smallest_sleep_ns, duration_ns);
        if (self.sleep_calls == 1) {
            if (self.cancel_on_first_sleep) |context| context.cancel();
        }
        if (self.zero_progress_sleeps > 0) {
            self.zero_progress_sleeps -= 1;
            return;
        }
        self.now_ns +|= duration_ns;
    }
};

const FakeResolverError = error{ResolverFailed};

fn failAfterCancelling(token: *types.CancellationToken) FakeResolverError!u8 {
    token.cancel();
    return error.ResolverFailed;
}

fn failAfterExpiring(context: *IoContext) FakeResolverError!u8 {
    context.setPhaseDeadline(Deadline.at(0));
    return error.ResolverFailed;
}

test "IoContext observes already-cancelled state" {
    var external = types.CancellationToken.init();
    external.cancel();

    var context = IoContext.init(.{ .external_cancel = &external });
    try std.testing.expect(context.isCancelled());
    try std.testing.expectError(error.Cancelled, context.checkAt(0));

    var local = IoContext.init(.{});
    local.cancel();
    try std.testing.expect(local.isLocallyCancelled());
    try std.testing.expectError(error.Cancelled, local.checkAt(0));
}

test "IoContext cancellation interrupts bounded wait" {
    var context = IoContext.init(.{});
    var clock = FakeClock{ .cancel_on_first_sleep = &context };

    try std.testing.expectError(error.Cancelled, context.waitForNsWithClock(100, &clock));
    try std.testing.expectEqual(@as(usize, 1), clock.sleep_calls);
    try std.testing.expect(clock.smallest_sleep_ns > 0);
}

test "IoContext selects phase and request deadlines deterministically" {
    var context = IoContext.init(.{
        .request_deadline = Deadline.at(20),
        .phase_deadline = Deadline.at(10),
    });
    try std.testing.expectEqual(DeadlineSource.phase, context.selectedDeadline().?.source);
    try std.testing.expectEqual(@as(?u64, 3), context.remainingNsAt(7));

    context.setPhaseDeadline(Deadline.at(30));
    try std.testing.expectEqual(DeadlineSource.request, context.selectedDeadline().?.source);

    context.setPhaseDeadline(Deadline.at(20));
    try std.testing.expectEqual(DeadlineSource.request, context.selectedDeadline().?.source);
}

test "IoContext timeout boundary and cancellation precedence" {
    var context = IoContext.init(.{ .request_deadline = Deadline.at(100) });
    try context.checkAt(99);
    try std.testing.expectError(error.Timeout, context.checkAt(100));
    try std.testing.expectEqual(DeadlineSource.request, context.expiredDeadlineAt(100).?);

    context.cancel();
    try std.testing.expectError(error.Cancelled, context.checkAt(100));
}

test "blocking result unwrap gives context state precedence over resolver error" {
    var token = types.CancellationToken.init();
    const cancelled = IoContext.init(.{ .external_cancel = &token });
    const cancelled_result = failAfterCancelling(&token);
    try std.testing.expectError(
        error.Cancelled,
        cancelled.unwrapAfterBlocking(u8, cancelled_result),
    );

    var expired = IoContext.init(.{});
    const expired_result = failAfterExpiring(&expired);
    try std.testing.expectError(
        error.Timeout,
        expired.unwrapAfterBlocking(u8, expired_result),
    );

    const active = IoContext.init(.{});
    const resolver_result: FakeResolverError!u8 = error.ResolverFailed;
    try std.testing.expectError(
        error.ResolverFailed,
        active.unwrapAfterBlocking(u8, resolver_result),
    );
}

test "deadline construction saturates on overflow" {
    const max = std.math.maxInt(u64);
    try std.testing.expectEqual(max, Deadline.afterNsAt(max - 5, 10).at_ns);
    try std.testing.expectEqual(max, Deadline.afterMsAt(max - 1, 1).at_ns);
    try std.testing.expectEqual(max, millisecondsToNanoseconds(max));
    try std.testing.expectEqual(@as(u64, 0), Deadline.at(4).remainingNsAt(5));
}

test "IoContext cancel does not mutate borrowed external token" {
    var external = types.CancellationToken.init();
    var context = IoContext.init(.{ .external_cancel = &external });

    context.cancel();
    try std.testing.expect(context.isLocallyCancelled());
    try std.testing.expect(!external.isCancelled());
}

test "bounded wait avoids busy-spin after a zero-progress sleep" {
    const wait_ns = 2 * max_wait_slice_ns + 1;
    var context = IoContext.init(.{});
    var clock = FakeClock{ .zero_progress_sleeps = 1 };

    try context.waitForNsWithClock(wait_ns, &clock);
    try std.testing.expectEqual(@as(usize, 4), clock.sleep_calls);
    try std.testing.expect(clock.smallest_sleep_ns > 0);
    try std.testing.expectEqual(wait_ns, clock.now_ns);
}

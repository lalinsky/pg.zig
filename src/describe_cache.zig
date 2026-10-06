const std = @import("std");
const lib = @import("lib.zig");

const Stmt = lib.Stmt;
const Allocator = std.mem.Allocator;

// The statement descriptions used by the `describe_cache` query option, keyed
// by SQL and evicting the least recently used once `capacity` is reached, like
// pgx's description cache.
pub const DescribeCache = struct {
    capacity: u16,
    map: std.StringHashMapUnmanaged(*Entry) = .empty,
    // Most recently used first.
    lru: std.DoublyLinkedList = .{},

    pub const Entry = struct {
        // Owned, and the map's key.
        sql: []const u8,
        describe: Stmt.Describe,
        node: std.DoublyLinkedList.Node = .{},
    };

    pub fn init(capacity: u16) DescribeCache {
        return .{ .capacity = capacity };
    }

    pub fn deinit(self: *DescribeCache, allocator: Allocator) void {
        while (self.lru.pop()) |node| {
            destroy(allocator, @fieldParentPtr("node", node));
        }
        self.map.deinit(allocator);
    }

    pub fn get(self: *DescribeCache, sql: []const u8) ?*Entry {
        const entry = self.map.get(sql) orelse return null;
        self.lru.remove(&entry.node);
        self.lru.prepend(&entry.node);
        return entry;
    }

    // Takes ownership of describe.arena, unless it fails.
    pub fn put(self: *DescribeCache, allocator: Allocator, sql: []const u8, describe: Stmt.Describe) !*Entry {
        lib.assert(self.capacity > 0);
        lib.assert(self.map.get(sql) == null);

        try self.map.ensureUnusedCapacity(allocator, 1);

        const owned_sql = try allocator.dupe(u8, sql);
        errdefer allocator.free(owned_sql);

        const entry = try allocator.create(Entry);
        entry.* = .{ .sql = owned_sql, .describe = describe };

        if (self.map.count() >= self.capacity) {
            const oldest: *Entry = @fieldParentPtr("node", self.lru.last.?);
            self.remove(allocator, oldest);
        }
        self.map.putAssumeCapacityNoClobber(owned_sql, entry);
        self.lru.prepend(&entry.node);
        return entry;
    }

    pub fn remove(self: *DescribeCache, allocator: Allocator, entry: *Entry) void {
        _ = self.map.remove(entry.sql);
        self.lru.remove(&entry.node);
        destroy(allocator, entry);
    }

    // Removes the entry for sql, if there is one.
    pub fn invalidate(self: *DescribeCache, allocator: Allocator, sql: []const u8) void {
        const entry = self.map.get(sql) orelse return;
        self.remove(allocator, entry);
    }

    fn destroy(allocator: Allocator, entry: *Entry) void {
        entry.describe.arena.deinit();
        allocator.free(entry.sql);
        allocator.destroy(entry);
    }
};

const t = lib.testing;
test "DescribeCache: evicts the least recently used" {
    const allocator = t.allocator;
    var cache = DescribeCache.init(2);
    defer cache.deinit(allocator);

    const empty: Stmt.Describe = .{ .arena = .init(allocator), .param_oids = &.{}, .result_state = undefined };
    _ = try cache.put(allocator, "a", empty);
    _ = try cache.put(allocator, "b", .{ .arena = .init(allocator), .param_oids = &.{}, .result_state = undefined });
    // "a" is now the most recently used, so "b" goes.
    try t.expectEqual(true, cache.get("a") != null);
    _ = try cache.put(allocator, "c", .{ .arena = .init(allocator), .param_oids = &.{}, .result_state = undefined });

    try t.expectEqual(2, cache.map.count());
    try t.expectEqual(true, cache.get("a") != null);
    try t.expectEqual(true, cache.get("b") == null);
    try t.expectEqual(true, cache.get("c") != null);

    cache.invalidate(allocator, "a");
    cache.invalidate(allocator, "missing");
    try t.expectEqual(1, cache.map.count());
    try t.expectEqual(true, cache.get("a") == null);
}

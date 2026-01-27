const std = @import("std");
const time = std.time;
const mem = std.mem;

const CustomChaCha = @import("chacha20.zig").ChaCha20;
const CustomPoly1305 = @import("poly1305.zig").Poly1305;

const DATA_SIZE = 1024 * 1024 * 256 * 32;
const CHUNK_SIZE = 4096;

pub fn main() !void {
    var buf: [4096]u8 = undefined;
    var handle = std.fs.File.stdout().writer(&buf);
    const stdout: *std.io.Writer = &handle.interface;

    var key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    std.crypto.random.bytes(&key);
    std.crypto.random.bytes(&nonce);

    const allocator = std.heap.page_allocator;
    const input = try allocator.alloc(u8, CHUNK_SIZE);
    const output = try allocator.alloc(u8, CHUNK_SIZE);
    defer allocator.free(input);
    defer allocator.free(output);

    std.crypto.random.bytes(input);

    // try stdout.print("\nRunning ChaCha20 Benchmark...\n", .{});
    // try stdout.print("Data Size: {d} MB | Chunk Size: {d} KB\n", .{ DATA_SIZE / 1024 / 1024, CHUNK_SIZE / 1024 });
    // try stdout.print("--------------------------------------------------\n", .{});
    // try stdout.flush();

    var timer = try time.Timer.start();
    {
        var counter: u32 = 0;
        const cipher = std.crypto.stream.chacha.ChaCha20IETF;
        cipher.xor(output, input, counter, key, nonce);
        counter += 1;

        var total_bytes: usize = 0;

        while (total_bytes < DATA_SIZE) {
            cipher.xor(output, input, counter, key, nonce);
            counter += 1;

            mem.doNotOptimizeAway(output);

            total_bytes += CHUNK_SIZE;
        }

        // printStats(stdout, "StdLib ", total_bytes, ns);
    }

    const ns_chacha_std = timer.read();

    try stdout.flush();

    timer = try time.Timer.start();
    {
        var cipher = CustomChaCha.init(&key, &nonce, 0);
        cipher.xor(output, input);

        var total_bytes: usize = 0;

        while (total_bytes < DATA_SIZE) {
            cipher.xor(output, input);

            mem.doNotOptimizeAway(output);

            total_bytes += CHUNK_SIZE;
        }

        // printStats(stdout, "Custom Impl ", total_bytes, ns);
    }

    const ns_chacha_custom = timer.read();
    // try stdout.flush();
    // try stdout.print("\nRunning Poly1305 Benchmark...\n", .{});
    // try stdout.print("--------------------------------------------------\n", .{});
    // try stdout.flush();
    const size = 256 * 1024 * 1024 * 16;
    const buffer = try allocator.alloc(u8, size);
    defer allocator.free(buffer);
    @memset(buffer, 0xAA);

    var tag: [16]u8 = undefined;

    timer = try time.Timer.start();
    {
        var poly = std.crypto.onetimeauth.Poly1305.init(&key);
        poly.update(buffer);
        poly.final(&tag);
        std.mem.doNotOptimizeAway(&tag);

        // printStats(stdout, "StdLib Poly1305", size, ns);
    }

    const ns_poly_std = timer.read();

    timer = try time.Timer.start();
    {
        var poly = CustomPoly1305.init(&key);
        poly.update(buffer);
        poly.finish(&tag);
        std.mem.doNotOptimizeAway(&tag);
        // printStats(stdout, "Custom Poly1305", size, ns);
    }

    const ns_poly_custom = timer.read();
    const size_gb = @as(f64, @floatFromInt(DATA_SIZE)) / 1_000_000_000.0;

    const results = .{
        .timestamp = std.time.timestamp(),
        .chacha_std_gbps = size_gb / (@as(f64, @floatFromInt(ns_chacha_std)) / 1e9),
        .chacha_custom_gbps = size_gb / (@as(f64, @floatFromInt(ns_chacha_custom)) / 1e9),
        .poly_std_gbps = size_gb / (@as(f64, @floatFromInt(ns_poly_std)) / 1e9),
        .poly_custom_gbps = size_gb / (@as(f64, @floatFromInt(ns_poly_custom)) / 1e9),
    };

    var sj: std.json.Stringify = .{ .writer = stdout, .options = .{} };
    try sj.write(results);

    try stdout.flush();
}

fn printStats(writer: anytype, name: []const u8, bytes: usize, ns: u64) void {
    const seconds = @as(f64, @floatFromInt(ns)) / 1_000_000_000.0;
    const mb = @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
    const speed = mb / seconds;

    writer.print("{s} : {d:.2} MB/s  ({d:.4} seconds)\n", .{ name, speed, seconds }) catch {};
}

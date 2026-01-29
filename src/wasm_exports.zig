const std = @import("std");
const ChaCha20 = @import("chacha20.zig").ChaCha20;
const Poly1305 = @import("poly1305.zig").Poly1305;
const Csrng = @import("csrng.zig").Csrng;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

var global_csrng: ?Csrng = null;

export fn alloc(len: usize) [*]u8 {
    const slice = allocator.alloc(u8, len) catch @panic("OOM");
    return slice.ptr;
}

export fn free(ptr: [*]u8, len: usize) void {
    allocator.free(ptr[0..len]);
}
export fn csrng_init(seed_ptr: [*]const u8) void {
    const seed = seed_ptr[0..32];
    global_csrng = Csrng.init(seed);
}

export fn csrng_fill(dest_ptr: [*]u8, len: usize) void {
    if (global_csrng) |*rng| {
        const dest = dest_ptr[0..len];
        rng.fill(dest);
    } else {
        @panic("CSRNG not initialized! Call csrng_init first.");
    }
}

export fn chacha20_xor(
    key_ptr: [*]const u8,
    nonce_ptr: [*]const u8,
    counter: u32,
    input_ptr: [*]const u8,
    input_len: usize,
    dest_ptr: [*]u8,
) void {
    const key = key_ptr[0..32];
    const nonce = nonce_ptr[0..12];
    const input = input_ptr[0..input_len];
    const dest = dest_ptr[0..input_len];

    var cipher = ChaCha20.init(key, nonce, counter);
    cipher.xor(dest, input);
}

export fn poly1305_init(key_ptr: [*]const u8) *Poly1305 {
    const ctx = allocator.create(Poly1305) catch @panic("OOM");

    const key = key_ptr[0..32];
    ctx.* = Poly1305.init(key);
    return ctx;
}

export fn poly1305_update(ctx: *Poly1305, input_ptr: [*]const u8, len: usize) void {
    const input = input_ptr[0..len];
    ctx.update(input);
}

export fn poly1305_final(ctx: *Poly1305, tag_ptr: [*]u8) void {
    const tag = tag_ptr[0..16];

    ctx.finish(tag);

    allocator.destroy(ctx);
}

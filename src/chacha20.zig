const std = @import("std");

pub const ChaCha20 = struct {
    state: [4]@Vector(4, u32),

    const constants = @Vector(4, u32){
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    };

    const one_vec = @Vector(4, u32){ 1, 0, 0, 0 };
    const two_vec = @Vector(4, u32){ 2, 0, 0, 0 };

    pub fn init(key: *const [32]u8, nonce: *const [12]u8, counter: u32) ChaCha20 {
        var state: [4]@Vector(4, u32) = undefined;

        state[0] = constants;

        //does this become single copy? (have to check)
        //not in hot path but still
        const k0 = std.mem.bytesAsSlice(u32, key[0..16]);
        const k1 = std.mem.bytesAsSlice(u32, key[16..32]);
        state[1] = @Vector(4, u32){ k0[0], k0[1], k0[2], k0[3] };
        state[2] = @Vector(4, u32){ k1[0], k1[1], k1[2], k1[3] };

        const n = std.mem.bytesAsSlice(u32, nonce[0..12]);
        state[3] = @Vector(4, u32){ counter, n[0], n[1], n[2] };

        return ChaCha20{ .state = state };
    }
    inline fn quarterRound256(a: *@Vector(8, u32), b: *@Vector(8, u32), c: *@Vector(8, u32), d: *@Vector(8, u32)) void {
        @setEvalBranchQuota(10000);
        a.* +%= b.*;
        d.* ^= a.*;
        d.* = rotl256(d.*, 16);
        c.* +%= d.*;
        b.* ^= c.*;
        b.* = rotl256(b.*, 12);
        a.* +%= b.*;
        d.* ^= a.*;
        d.* = rotl256(d.*, 8);
        c.* +%= d.*;
        b.* ^= c.*;
        b.* = rotl256(b.*, 7);
    }

    inline fn quarterRound128(a: *@Vector(4, u32), b: *@Vector(4, u32), c: *@Vector(4, u32), d: *@Vector(4, u32)) void {
        @setEvalBranchQuota(10000);
        a.* +%= b.*;
        d.* ^= a.*;
        d.* = rotl128(d.*, 16);
        c.* +%= d.*;
        b.* ^= c.*;
        b.* = rotl128(b.*, 12);
        a.* +%= b.*;
        d.* ^= a.*;
        d.* = rotl128(d.*, 8);
        c.* +%= d.*;
        b.* ^= c.*;
        b.* = rotl128(b.*, 7);
    }

    inline fn rotl256(v: @Vector(8, u32), comptime amt: u5) @Vector(8, u32) {
        const shift_l = @as(@Vector(8, u5), @splat(amt));
        const shift_r = @as(@Vector(8, u5), @splat(0 -% amt));
        return (v << shift_l) | (v >> shift_r);
    }

    inline fn rotl128(v: @Vector(4, u32), comptime amt: u5) @Vector(4, u32) {
        const shift_l = @as(@Vector(4, u5), @splat(amt));
        const shift_r = @as(@Vector(4, u5), @splat(0 -% amt));
        return (v << shift_l) | (v >> shift_r);
    }

    pub fn xor(self: *ChaCha20, dest: []u8, input: []const u8) void {
        var i: usize = 0;
        const dup_mask = @Vector(8, i32){ 0, 1, 2, 3, 0, 1, 2, 3 };

        const ctr_offset_1 = @Vector(8, u32){ 0, 0, 0, 0, 1, 0, 0, 0 };
        const ctr_offset_2 = @Vector(8, u32){ 2, 0, 0, 0, 3, 0, 0, 0 };

        const ctr_offset_3 = @Vector(8, u32){ 4, 0, 0, 0, 5, 0, 0, 0 };

        const mask_b = @Vector(8, i32){ 1, 2, 3, 0, 5, 6, 7, 4 };
        const mask_c = @Vector(8, i32){ 2, 3, 0, 1, 6, 7, 4, 5 };
        const mask_d = @Vector(8, i32){ 3, 0, 1, 2, 7, 4, 5, 6 };

        const mask_b_inv = @Vector(8, i32){ 3, 0, 1, 2, 7, 4, 5, 6 };
        const mask_c_inv = @Vector(8, i32){ 2, 3, 0, 1, 6, 7, 4, 5 };
        const mask_d_inv = @Vector(8, i32){ 1, 2, 3, 0, 5, 6, 7, 4 };
        const shuf_lo_lo = @Vector(8, i32){ 0, 1, 2, 3, ~@as(i32, 0), ~@as(i32, 1), ~@as(i32, 2), ~@as(i32, 3) };
        const shuf_hi_hi = @Vector(8, i32){ 4, 5, 6, 7, ~@as(i32, 4), ~@as(i32, 5), ~@as(i32, 6), ~@as(i32, 7) };

        while (i + 512 <= input.len) {
            var a1 = @shuffle(u32, self.state[0], undefined, dup_mask);
            var b1 = @shuffle(u32, self.state[1], undefined, dup_mask);
            var c1 = @shuffle(u32, self.state[2], undefined, dup_mask);
            var d1 = @shuffle(u32, self.state[3], undefined, dup_mask) +% @Vector(8, u32){ 0, 0, 0, 0, 1, 0, 0, 0 };

            var a2 = a1;
            var b2 = b1;
            var c2 = c1;
            var d2 = @shuffle(u32, self.state[3], undefined, dup_mask) +% @Vector(8, u32){ 2, 0, 0, 0, 3, 0, 0, 0 };

            var a3 = a1;
            var b3 = b1;
            var c3 = c1;
            var d3 = @shuffle(u32, self.state[3], undefined, dup_mask) +% @Vector(8, u32){ 4, 0, 0, 0, 5, 0, 0, 0 };

            var a4 = a1;
            var b4 = b1;
            var c4 = c1;
            var d4 = @shuffle(u32, self.state[3], undefined, dup_mask) +% @Vector(8, u32){ 6, 0, 0, 0, 7, 0, 0, 0 };

            const init_a1 = a1;
            const init_b1 = b1;
            const init_c1 = c1;
            const init_d1 = d1;
            const init_a2 = a2;
            const init_b2 = b2;
            const init_c2 = c2;
            const init_d2 = d2;
            const init_a3 = a3;
            const init_b3 = b3;
            const init_c3 = c3;
            const init_d3 = d3;
            const init_a4 = a4;
            const init_b4 = b4;
            const init_c4 = c4;
            const init_d4 = d4;

            inline for (0..10) |_| {
                quarterRound256(&a1, &b1, &c1, &d1);
                quarterRound256(&a2, &b2, &c2, &d2);
                quarterRound256(&a3, &b3, &c3, &d3);
                quarterRound256(&a4, &b4, &c4, &d4);

                b1 = @shuffle(u32, b1, undefined, mask_b);
                b2 = @shuffle(u32, b2, undefined, mask_b);
                b3 = @shuffle(u32, b3, undefined, mask_b);
                b4 = @shuffle(u32, b4, undefined, mask_b);

                c1 = @shuffle(u32, c1, undefined, mask_c);
                c2 = @shuffle(u32, c2, undefined, mask_c);
                c3 = @shuffle(u32, c3, undefined, mask_c);
                c4 = @shuffle(u32, c4, undefined, mask_c);

                d1 = @shuffle(u32, d1, undefined, mask_d);
                d2 = @shuffle(u32, d2, undefined, mask_d);
                d3 = @shuffle(u32, d3, undefined, mask_d);
                d4 = @shuffle(u32, d4, undefined, mask_d);

                quarterRound256(&a1, &b1, &c1, &d1);
                quarterRound256(&a2, &b2, &c2, &d2);
                quarterRound256(&a3, &b3, &c3, &d3);
                quarterRound256(&a4, &b4, &c4, &d4);

                b1 = @shuffle(u32, b1, undefined, mask_b_inv);
                b2 = @shuffle(u32, b2, undefined, mask_b_inv);
                b3 = @shuffle(u32, b3, undefined, mask_b_inv);
                b4 = @shuffle(u32, b4, undefined, mask_b_inv);

                c1 = @shuffle(u32, c1, undefined, mask_c_inv);
                c2 = @shuffle(u32, c2, undefined, mask_c_inv);
                c3 = @shuffle(u32, c3, undefined, mask_c_inv);
                c4 = @shuffle(u32, c4, undefined, mask_c_inv);

                d1 = @shuffle(u32, d1, undefined, mask_d_inv);
                d2 = @shuffle(u32, d2, undefined, mask_d_inv);
                d3 = @shuffle(u32, d3, undefined, mask_d_inv);
                d4 = @shuffle(u32, d4, undefined, mask_d_inv);
            }

            a1 +%= init_a1;
            b1 +%= init_b1;
            c1 +%= init_c1;
            d1 +%= init_d1;
            a2 +%= init_a2;
            b2 +%= init_b2;
            c2 +%= init_c2;
            d2 +%= init_d2;
            a3 +%= init_a3;
            b3 +%= init_b3;
            c3 +%= init_c3;
            d3 +%= init_d3;
            a4 +%= init_a4;
            b4 +%= init_b4;
            c4 +%= init_c4;
            d4 +%= init_d4;

            const in_p = @as([*]align(1) const @Vector(8, u32), @ptrCast(input[i..].ptr));
            const out_p = @as([*]align(1) @Vector(8, u32), @ptrCast(dest[i..].ptr));

            out_p[0] = in_p[0] ^ @shuffle(u32, a1, b1, shuf_lo_lo);
            out_p[1] = in_p[1] ^ @shuffle(u32, c1, d1, shuf_lo_lo);
            out_p[2] = in_p[2] ^ @shuffle(u32, a1, b1, shuf_hi_hi);
            out_p[3] = in_p[3] ^ @shuffle(u32, c1, d1, shuf_hi_hi);

            out_p[4] = in_p[4] ^ @shuffle(u32, a2, b2, shuf_lo_lo);
            out_p[5] = in_p[5] ^ @shuffle(u32, c2, d2, shuf_lo_lo);
            out_p[6] = in_p[6] ^ @shuffle(u32, a2, b2, shuf_hi_hi);
            out_p[7] = in_p[7] ^ @shuffle(u32, c2, d2, shuf_hi_hi);

            out_p[8] = in_p[8] ^ @shuffle(u32, a3, b3, shuf_lo_lo);
            out_p[9] = in_p[9] ^ @shuffle(u32, c3, d3, shuf_lo_lo);
            out_p[10] = in_p[10] ^ @shuffle(u32, a3, b3, shuf_hi_hi);
            out_p[11] = in_p[11] ^ @shuffle(u32, c3, d3, shuf_hi_hi);

            out_p[12] = in_p[12] ^ @shuffle(u32, a4, b4, shuf_lo_lo);
            out_p[13] = in_p[13] ^ @shuffle(u32, c4, d4, shuf_lo_lo);
            out_p[14] = in_p[14] ^ @shuffle(u32, a4, b4, shuf_hi_hi);
            out_p[15] = in_p[15] ^ @shuffle(u32, c4, d4, shuf_hi_hi);

            self.state[3] +%= @Vector(4, u32){ 8, 0, 0, 0 };
            i += 512;
        }

        while (i + 384 <= input.len) {
            var a1 = @shuffle(u32, self.state[0], undefined, dup_mask);
            var b1 = @shuffle(u32, self.state[1], undefined, dup_mask);
            var c1 = @shuffle(u32, self.state[2], undefined, dup_mask);
            var d1 = @shuffle(u32, self.state[3], undefined, dup_mask) +% ctr_offset_1;

            var a2 = a1;
            var b2 = b1;
            var c2 = c1;
            var d2 = @shuffle(u32, self.state[3], undefined, dup_mask) +% ctr_offset_2;

            var a3 = a1;
            var b3 = b1;
            var c3 = c1;
            var d3 = @shuffle(u32, self.state[3], undefined, dup_mask) +% ctr_offset_3;

            const init_a1 = a1;
            const init_b1 = b1;
            const init_c1 = c1;
            const init_d1 = d1;
            const init_a2 = a2;
            const init_b2 = b2;
            const init_c2 = c2;
            const init_d2 = d2;
            const init_a3 = a3;
            const init_b3 = b3;
            const init_c3 = c3;
            const init_d3 = d3;

            inline for (0..10) |_| {
                quarterRound256(&a1, &b1, &c1, &d1);
                quarterRound256(&a2, &b2, &c2, &d2);
                quarterRound256(&a3, &b3, &c3, &d3);

                b1 = @shuffle(u32, b1, undefined, mask_b);
                b2 = @shuffle(u32, b2, undefined, mask_b);
                b3 = @shuffle(u32, b3, undefined, mask_b);

                c1 = @shuffle(u32, c1, undefined, mask_c);
                c2 = @shuffle(u32, c2, undefined, mask_c);
                c3 = @shuffle(u32, c3, undefined, mask_c);

                d1 = @shuffle(u32, d1, undefined, mask_d);
                d2 = @shuffle(u32, d2, undefined, mask_d);
                d3 = @shuffle(u32, d3, undefined, mask_d);

                quarterRound256(&a1, &b1, &c1, &d1);
                quarterRound256(&a2, &b2, &c2, &d2);
                quarterRound256(&a3, &b3, &c3, &d3);

                b1 = @shuffle(u32, b1, undefined, mask_b_inv);
                b2 = @shuffle(u32, b2, undefined, mask_b_inv);
                b3 = @shuffle(u32, b3, undefined, mask_b_inv);

                c1 = @shuffle(u32, c1, undefined, mask_c_inv);
                c2 = @shuffle(u32, c2, undefined, mask_c_inv);
                c3 = @shuffle(u32, c3, undefined, mask_c_inv);

                d1 = @shuffle(u32, d1, undefined, mask_d_inv);
                d2 = @shuffle(u32, d2, undefined, mask_d_inv);
                d3 = @shuffle(u32, d3, undefined, mask_d_inv);
            }

            a1 +%= init_a1;
            b1 +%= init_b1;
            c1 +%= init_c1;
            d1 +%= init_d1;
            a2 +%= init_a2;
            b2 +%= init_b2;
            c2 +%= init_c2;
            d2 +%= init_d2;
            a3 +%= init_a3;
            b3 +%= init_b3;
            c3 +%= init_c3;
            d3 +%= init_d3;

            const in_p = @as([*]align(1) const @Vector(8, u32), @ptrCast(input[i..].ptr));
            const out_p = @as([*]align(1) @Vector(8, u32), @ptrCast(dest[i..].ptr));

            out_p[0] = in_p[0] ^ @shuffle(u32, a1, b1, shuf_lo_lo);
            out_p[1] = in_p[1] ^ @shuffle(u32, c1, d1, shuf_lo_lo);
            out_p[2] = in_p[2] ^ @shuffle(u32, a1, b1, shuf_hi_hi);
            out_p[3] = in_p[3] ^ @shuffle(u32, c1, d1, shuf_hi_hi);

            out_p[4] = in_p[4] ^ @shuffle(u32, a2, b2, shuf_lo_lo);
            out_p[5] = in_p[5] ^ @shuffle(u32, c2, d2, shuf_lo_lo);
            out_p[6] = in_p[6] ^ @shuffle(u32, a2, b2, shuf_hi_hi);
            out_p[7] = in_p[7] ^ @shuffle(u32, c2, d2, shuf_hi_hi);

            out_p[8] = in_p[8] ^ @shuffle(u32, a3, b3, shuf_lo_lo);
            out_p[9] = in_p[9] ^ @shuffle(u32, c3, d3, shuf_lo_lo);
            out_p[10] = in_p[10] ^ @shuffle(u32, a3, b3, shuf_hi_hi);
            out_p[11] = in_p[11] ^ @shuffle(u32, c3, d3, shuf_hi_hi);

            self.state[3] +%= @Vector(4, u32){ 6, 0, 0, 0 };
            i += 384;
        }

        while (i + 256 <= input.len) {
            var a1 = @shuffle(u32, self.state[0], undefined, dup_mask);
            var b1 = @shuffle(u32, self.state[1], undefined, dup_mask);
            var c1 = @shuffle(u32, self.state[2], undefined, dup_mask);
            var d1 = @shuffle(u32, self.state[3], undefined, dup_mask) +% ctr_offset_1;

            var a2 = a1;
            var b2 = b1;
            var c2 = c1;
            var d2 = @shuffle(u32, self.state[3], undefined, dup_mask) +% ctr_offset_2;

            const init_a1 = a1;
            const init_b1 = b1;
            const init_c1 = c1;
            const init_d1 = d1;
            const init_a2 = a2;
            const init_b2 = b2;
            const init_c2 = c2;
            const init_d2 = d2;

            inline for (0..10) |_| {
                quarterRound256(&a1, &b1, &c1, &d1);
                quarterRound256(&a2, &b2, &c2, &d2);
                b1 = @shuffle(u32, b1, undefined, mask_b);
                b2 = @shuffle(u32, b2, undefined, mask_b);
                c1 = @shuffle(u32, c1, undefined, mask_c);
                c2 = @shuffle(u32, c2, undefined, mask_c);
                d1 = @shuffle(u32, d1, undefined, mask_d);
                d2 = @shuffle(u32, d2, undefined, mask_d);

                quarterRound256(&a1, &b1, &c1, &d1);
                quarterRound256(&a2, &b2, &c2, &d2);

                b1 = @shuffle(u32, b1, undefined, mask_b_inv);
                b2 = @shuffle(u32, b2, undefined, mask_b_inv);
                c1 = @shuffle(u32, c1, undefined, mask_c_inv);
                c2 = @shuffle(u32, c2, undefined, mask_c_inv);
                d1 = @shuffle(u32, d1, undefined, mask_d_inv);
                d2 = @shuffle(u32, d2, undefined, mask_d_inv);
            }

            a1 +%= init_a1;
            a2 +%= init_a2;
            b1 +%= init_b1;
            b2 +%= init_b2;
            c1 +%= init_c1;
            c2 +%= init_c2;
            d1 +%= init_d1;
            d2 +%= init_d2;

            const k_blk0_upper = @shuffle(u32, a1, b1, shuf_lo_lo);
            const k_blk0_lower = @shuffle(u32, c1, d1, shuf_lo_lo);

            const k_blk1_upper = @shuffle(u32, a1, b1, shuf_hi_hi);
            const k_blk1_lower = @shuffle(u32, c1, d1, shuf_hi_hi);

            const k_blk2_upper = @shuffle(u32, a2, b2, shuf_lo_lo);
            const k_blk2_lower = @shuffle(u32, c2, d2, shuf_lo_lo);

            const k_blk3_upper = @shuffle(u32, a2, b2, shuf_hi_hi);
            const k_blk3_lower = @shuffle(u32, c2, d2, shuf_hi_hi);

            const in_ptr = @as([*]align(1) const @Vector(8, u32), @ptrCast(input[i..].ptr));
            const out_ptr = @as([*]align(1) @Vector(8, u32), @ptrCast(dest[i..].ptr));

            out_ptr[0] = in_ptr[0] ^ k_blk0_upper;
            out_ptr[1] = in_ptr[1] ^ k_blk0_lower;

            out_ptr[2] = in_ptr[2] ^ k_blk1_upper;
            out_ptr[3] = in_ptr[3] ^ k_blk1_lower;

            out_ptr[4] = in_ptr[4] ^ k_blk2_upper;
            out_ptr[5] = in_ptr[5] ^ k_blk2_lower;

            out_ptr[6] = in_ptr[6] ^ k_blk3_upper;
            out_ptr[7] = in_ptr[7] ^ k_blk3_lower;

            self.state[3] +%= @Vector(4, u32){ 4, 0, 0, 0 };
            i += 256;
        }

        while (i + 128 <= input.len) {
            var a = @shuffle(u32, self.state[0], self.state[0], dup_mask);
            var b = @shuffle(u32, self.state[1], self.state[1], dup_mask);
            var c = @shuffle(u32, self.state[2], self.state[2], dup_mask);

            const d_base = @shuffle(u32, self.state[3], self.state[3], dup_mask);
            var d = d_base +% ctr_offset_1;

            const init_a = a;
            const init_b = b;
            const init_c = c;
            const init_d = d;

            inline for (0..10) |_| {
                quarterRound256(&a, &b, &c, &d);

                b = @shuffle(u32, b, undefined, mask_b);
                c = @shuffle(u32, c, undefined, mask_c);
                d = @shuffle(u32, d, undefined, mask_d);

                quarterRound256(&a, &b, &c, &d);

                b = @shuffle(u32, b, undefined, mask_b_inv);
                c = @shuffle(u32, c, undefined, mask_c_inv);
                d = @shuffle(u32, d, undefined, mask_d_inv);
            }

            a +%= init_a;
            b +%= init_b;
            c +%= init_c;
            d +%= init_d;

            const in_ptr = @as([*]align(1) const @Vector(8, u32), @ptrCast(input[i..].ptr));
            const out_ptr = @as([*]align(1) @Vector(8, u32), @ptrCast(dest[i..].ptr));

            out_ptr[0] = in_ptr[0] ^ a;
            out_ptr[1] = in_ptr[1] ^ b;
            out_ptr[2] = in_ptr[2] ^ c;
            out_ptr[3] = in_ptr[3] ^ d;

            self.state[3] = self.state[3] +% two_vec;
            i += 128;
        }

        while (i + 64 <= input.len) {
            var a = self.state[0];
            var b = self.state[1];
            var c = self.state[2];
            var d = self.state[3];

            inline for (0..10) |_| {
                quarterRound128(&a, &b, &c, &d);

                b = @shuffle(u32, b, undefined, [4]i32{ 1, 2, 3, 0 });
                c = @shuffle(u32, c, undefined, [4]i32{ 2, 3, 0, 1 });
                d = @shuffle(u32, d, undefined, [4]i32{ 3, 0, 1, 2 });

                quarterRound128(&a, &b, &c, &d);

                b = @shuffle(u32, b, undefined, [4]i32{ 3, 0, 1, 2 });
                c = @shuffle(u32, c, undefined, [4]i32{ 2, 3, 0, 1 });
                d = @shuffle(u32, d, undefined, [4]i32{ 1, 2, 3, 0 });
            }

            a +%= self.state[0];
            b +%= self.state[1];
            c +%= self.state[2];
            d +%= self.state[3];

            const in_ptr = @as([*]align(1) const @Vector(4, u32), @ptrCast(input[i..].ptr));
            const out_ptr = @as([*]align(1) @Vector(4, u32), @ptrCast(dest[i..].ptr));

            out_ptr[0] = in_ptr[0] ^ a;
            out_ptr[1] = in_ptr[1] ^ b;
            out_ptr[2] = in_ptr[2] ^ c;
            out_ptr[3] = in_ptr[3] ^ d;

            self.state[3] +%= one_vec;

            i += 64;
        }

        if (i < input.len) {
            var block: [64]u8 = undefined;
            var a = self.state[0];
            var b = self.state[1];
            var c = self.state[2];
            var d = self.state[3];
            inline for (0..10) |_| {
                quarterRound128(&a, &b, &c, &d);
                b = @shuffle(u32, b, undefined, [4]i32{ 1, 2, 3, 0 });
                c = @shuffle(u32, c, undefined, [4]i32{ 2, 3, 0, 1 });
                d = @shuffle(u32, d, undefined, [4]i32{ 3, 0, 1, 2 });
                quarterRound128(&a, &b, &c, &d);
                b = @shuffle(u32, b, undefined, [4]i32{ 3, 0, 1, 2 });
                c = @shuffle(u32, c, undefined, [4]i32{ 2, 3, 0, 1 });
                d = @shuffle(u32, d, undefined, [4]i32{ 1, 2, 3, 0 });
            }
            a +%= self.state[0];
            b +%= self.state[1];
            c +%= self.state[2];
            d +%= self.state[3];

            const rows = [4]@Vector(4, u32){ a, b, c, d };
            var ptr: [*]u8 = &block;
            inline for (rows) |row| {
                const arr: [4]u32 = row;
                inline for (arr) |val| {
                    std.mem.writeInt(u32, ptr[0..4], val, .little);
                    ptr += 4;
                }
            }

            while (i < input.len) : (i += 1) {
                dest[i] = input[i] ^ block[i % 64];
            }
        }
    }
};
const testing = std.testing;

pub fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        const byte_str = hex[i .. i + 2];
        out[i / 2] = std.fmt.parseInt(u8, byte_str, 16) catch unreachable;
    }
    return out;
}

test "Rfc Test Vector" {
    var key: [32]u8 = undefined;
    for (0..32) |i| key[i] = @as(u8, @intCast(i));

    const nonce = [12]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };

    const counter = 1;
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    const expected_hex =
        "6e2e359a2568f98041ba0728dd0d6981" ++
        "e97e7aec1d4360c20a27afccfd9fae0b" ++
        "f91b65c5524733ab8f593dabcd62b357" ++
        "1639d624e65152ab8f530c359f0861d8" ++
        "07ca0dbf500d6a6156a38e088a22b65e" ++
        "52bc514d16ccf806818ce91ab7793736" ++
        "5af90bbf74a35be6b40b8eedf2785e42" ++
        "874d";

    var chacha = ChaCha20.init(&key, &nonce, counter);
    var ciphertext = try testing.allocator.alloc(u8, plaintext.len);
    defer testing.allocator.free(ciphertext);

    chacha.xor(ciphertext, plaintext);

    const expected_bytes = hexToBytes(expected_hex);

    try testing.expectEqualSlices(u8, &expected_bytes, ciphertext[0..expected_bytes.len]);
}

test "Encrypt And Decrypt)" {
    const key = [_]u8{0x12} ** 32;
    const nonce = [_]u8{0x53} ** 12;

    const original_msg = "A" ** 70;

    var encrypted: [70]u8 = undefined;
    var decrypted: [70]u8 = undefined;

    var cipher1 = ChaCha20.init(&key, &nonce, 1);
    cipher1.xor(&encrypted, original_msg);

    var cipher2 = ChaCha20.init(&key, &nonce, 1);
    cipher2.xor(&decrypted, &encrypted);

    try testing.expectEqualStrings(original_msg, &decrypted);

    try testing.expect(!std.mem.eql(u8, original_msg, &encrypted));
}

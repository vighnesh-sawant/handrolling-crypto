const std = @import("std");

pub const Poly1305 = struct {
    h: u256 = 0,
    r: u128,
    s: u128,
    buffer: [16]u8 = undefined,
    buf_len: usize = 0,

    pub fn init(key: *const [32]u8) Poly1305 {
        var r = std.mem.readInt(u128, key[0..16], .little);
        const s = std.mem.readInt(u128, key[16..32], .little);

        r &= 0x0ffffffc0ffffffc0ffffffc0fffffff;

        return Poly1305{
            .r = r,
            .s = s,
            .h = 0,
        };
    }

    pub fn update(self: *Poly1305, msg: []const u8) void {
        var i: usize = 0;

        if (self.buf_len > 0) {
            const need = 16 - self.buf_len;
            if (msg.len < need) {
                @memcpy(self.buffer[self.buf_len..][0..msg.len], msg);
                self.buf_len += msg.len;
                return;
            }
            @memcpy(self.buffer[self.buf_len..][0..need], msg[0..need]);
            self.processBlock(&self.buffer, false);
            self.buf_len = 0;
            i += need;
        }

        while (i + 16 <= msg.len) {
            self.processBlock(msg[i..][0..16], false);
            i += 16;
        }

        if (i < msg.len) {
            const left = msg.len - i;
            @memcpy(self.buffer[0..left], msg[i..]);
            self.buf_len = left;
        }
    }

    pub fn finish(self: *Poly1305, mac: *[16]u8) void {
        if (self.buf_len > 0) {
            @memset(self.buffer[self.buf_len..], 0);

            self.buffer[self.buf_len] = 1;

            self.processBlock(&self.buffer, true);
        }

        var h = self.h;
        h = self.reduceStep(h);
        h = self.reduceStep(h);
        h = self.reduceStep(h);
        const P = (@as(u256, 1) << 130) - 5;

        if (h >= P) {
            h -= P;
        }

        const h_128: u128 = @truncate(h);
        const result = h_128 +% self.s;

        std.mem.writeInt(u128, mac, result, .little);
    }

    inline fn processBlock(self: *Poly1305, bytes: *const [16]u8, is_partial: bool) void {
        const n = std.mem.readInt(u128, bytes, .little);

        self.h += n;

        if (!is_partial) {
            self.h += (1 << 128);
        }

        self.h *= self.r;

        self.h = self.reduceStep(self.h);
    }

    inline fn reduceStep(self: *Poly1305, val: u256) u256 {
        _ = self;
        const mask = (@as(u256, 1) << 130) - 1;
        const low = val & mask;
        const high = val >> 130;

        return low + (high * 5);
    }
};

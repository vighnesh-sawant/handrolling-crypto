const std = @import("std");
const ChaCha20 = @import("root.zig").ChaCha20;

pub const Csrng = struct {
    cipher: ChaCha20,

    const zero_nonce = [_]u8{0} ** 12;

    pub fn init() !Csrng {
        var seed: [32]u8 = undefined;
        //blocking!
        try std.posix.getrandom(&seed);

        return Csrng{
            .cipher = ChaCha20.init(&seed, &zero_nonce, 0),
        };
    }

    pub fn fill(self: *Csrng, dest: []u8) void {
        @memset(dest, 0);

        self.cipher.xor(dest, dest);

        var new_key: [32]u8 = undefined;
        @memset(&new_key, 0);

        self.cipher.xor(&new_key, &new_key);

        self.cipher = ChaCha20.init(&new_key, &zero_nonce, 0);
    }

    pub fn random(self: *Csrng) std.Random {
        return std.Random.init(self, fillVoid);
    }

    fn fillVoid(ptr: *Csrng, buf: []u8) void {
        ptr.fill(buf);
    }
};

test "CSRNG test" {
    var csrng = try Csrng.init();

    const r = csrng.random();

    const my_int = r.int(u64);
    const coin_flip = r.boolean();
    const dice_roll = r.intRangeAtMost(u8, 1, 6);

    std.debug.print("\nRandom u64: {}\n", .{my_int});
    std.debug.print("Coin flip: {}\n", .{coin_flip});
    std.debug.print("Dice roll: {}\n", .{dice_roll});

    var buf: [1024]u8 = undefined;
    csrng.fill(&buf);
}

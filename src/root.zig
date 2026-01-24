const std = @import("std");

pub const ChaCha20 = struct {
    state: [4]@Vector(4, u32),

    const constants = @Vector(4, u32){
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    };

    pub fn init(key: *const [32]u8, nonce: *const [12]u8, counter: u32) ChaCha20 {
        var state: [4]@Vector(4, u32) = undefined;

        state[0] = constants;

        const k0 = std.mem.bytesAsSlice(u32, key[0..16]);
        const k1 = std.mem.bytesAsSlice(u32, key[16..32]);
        state[1] = @Vector(4, u32){ k0[0], k0[1], k0[2], k0[3] };
        state[2] = @Vector(4, u32){ k1[0], k1[1], k1[2], k1[3] };

        const n = std.mem.bytesAsSlice(u32, nonce[0..12]);
        state[3] = @Vector(4, u32){ counter, n[0], n[1], n[2] };

        return ChaCha20{ .state = state };
    }
    fn quarterRound(a: *@Vector(4, u32), b: *@Vector(4, u32), c: *@Vector(4, u32), d: *@Vector(4, u32)) void {
        a.* +%= b.*;
        d.* ^= a.*;
        d.* = rotlVector(d.*, 16);
        c.* +%= d.*;
        b.* ^= c.*;
        b.* = rotlVector(b.*, 12);
        a.* +%= b.*;
        d.* ^= a.*;
        d.* = rotlVector(d.*, 8);
        c.* +%= d.*;
        b.* ^= c.*;
        b.* = rotlVector(b.*, 7);
    }

    fn rotlVector(v: @Vector(4, u32), amt: u5) @Vector(4, u32) {
        const shift_l = @as(@Vector(4, u5), @splat(amt));
        const shift_r = @as(@Vector(4, u5), @splat(0 -% amt));
        return (v << shift_l) | (v >> shift_r);
    }

    fn generateBlock(self: *ChaCha20, output: *[64]u8) void {
        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];

        for (0..10) |_| {
            quarterRound(&a, &b, &c, &d);

            b = @shuffle(u32, b, undefined, [4]i32{ 1, 2, 3, 0 });
            c = @shuffle(u32, c, undefined, [4]i32{ 2, 3, 0, 1 });
            d = @shuffle(u32, d, undefined, [4]i32{ 3, 0, 1, 2 });

            quarterRound(&a, &b, &c, &d);

            b = @shuffle(u32, b, undefined, [4]i32{ 3, 0, 1, 2 });
            c = @shuffle(u32, c, undefined, [4]i32{ 2, 3, 0, 1 });
            d = @shuffle(u32, d, undefined, [4]i32{ 1, 2, 3, 0 });
        }
        a +%= self.state[0];
        b +%= self.state[1];
        c +%= self.state[2];
        d +%= self.state[3];

        const rows = [4]@Vector(4, u32){ a, b, c, d };
        var ptr: [*]u8 = output;

        inline for (rows) |row| {
            const arr: [4]u32 = row;
            for (arr) |val| {
                std.mem.writeInt(u32, ptr[0..4], val, .little);
                ptr += 4;
            }
        }

        var last_row: [4]u32 = self.state[3];
        last_row[0] +%= 1;
        self.state[3] = last_row;
    }

    pub fn xor(self: *ChaCha20, dest: []u8, input: []const u8) void {
        var block: [64]u8 = undefined;
        var i: usize = 0;

        while (i < input.len) {
            self.generateBlock(&block);

            const remaining = input.len - i;
            const size = if (remaining < 64) remaining else 64;

            for (0..size) |j| {
                dest[i + j] = input[i + j] ^ block[j];
            }

            i += size;
        }
    }
};
const testing = std.testing;

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

    var expected_bytes: [expected_hex.len / 2]u8 = undefined;

    var i: usize = 0;
    while (i < expected_hex.len) : (i += 2) {
        const h = expected_hex[i];
        const l = expected_hex[i + 1];

        const h_val: u8 = if (h >= '0' and h <= '9') h - '0' else h - 'a' + 10;
        const l_val: u8 = if (l >= '0' and l <= '9') l - '0' else l - 'a' + 10;

        expected_bytes[i / 2] = (h_val << 4) | l_val;
    }

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

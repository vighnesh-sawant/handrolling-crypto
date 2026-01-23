const std = @import("std");

pub const ChaCha20 = struct {
    state: [16]u32,

    const constants = [4]u32{
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    };

    pub fn init(key: *const [32]u8, nonce: *const [12]u8, counter: u32) ChaCha20 {
        var state: [16]u32 = undefined;

        state[0] = constants[0];
        state[1] = constants[1];
        state[2] = constants[2];
        state[3] = constants[3];

        for (0..8) |i| {
            state[4 + i] = std.mem.readInt(u32, key[i * 4 ..][0..4], .little);
        }

        state[12] = counter;

        for (0..3) |i| {
            state[13 + i] = std.mem.readInt(u32, nonce[i * 4 ..][0..4], .little);
        }

        return ChaCha20{ .state = state };
    }
    fn quarterRound(x: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
        x[a] +%= x[b];
        x[d] ^= x[a];
        x[d] = std.math.rotl(u32, x[d], 16);

        x[c] +%= x[d];
        x[b] ^= x[c];
        x[b] = std.math.rotl(u32, x[b], 12);

        x[a] +%= x[b];
        x[d] ^= x[a];
        x[d] = std.math.rotl(u32, x[d], 8);

        x[c] +%= x[d];
        x[b] ^= x[c];
        x[b] = std.math.rotl(u32, x[b], 7);
    }
    fn generateBlock(self: *ChaCha20, output: *[64]u8) void {
        var x = self.state;

        for (0..10) |_| {
            quarterRound(&x, 0, 4, 8, 12);
            quarterRound(&x, 1, 5, 9, 13);
            quarterRound(&x, 2, 6, 10, 14);
            quarterRound(&x, 3, 7, 11, 15);

            quarterRound(&x, 0, 5, 10, 15);
            quarterRound(&x, 1, 6, 11, 12);
            quarterRound(&x, 2, 7, 8, 13);
            quarterRound(&x, 3, 4, 9, 14);
        }

        for (0..16) |i| {
            x[i] +%= self.state[i];
        }

        for (0..16) |i| {
            std.mem.writeInt(u32, output[i * 4 ..][0..4], x[i], .little);
        }

        self.state[12] +%= 1;
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

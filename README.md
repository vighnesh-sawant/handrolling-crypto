# handrolling-crypto
Well I somehow managed to make a faster chacha20 than the zig std lib!
It may not be secure though lol.
Main learning was how amazing ILP(instruction level parrallesim) is!
The dev needs to put thought it to achieve it also!
# ChaCha20
This is an AXR cipher which I implemented, it has the same security guarentees as of AES but is faster on devices which do not have a hardware accelerator for AES (certain IOT devices)
I made it faster than the std lib by interleaving multiple blocks while using simd such that the simd registers max out.
This allows the compiler to place instructions such that the cpu pipeline is full.
The limit is 6 blocks as each pair of blocks require 4 simd registers, we have 16 on avx2, so leaving 4 for temporary values turns out to be good.
I hit a 3.68 smth IPC which is quite high!
I have a device with a AVX2 so I could not do AVX-512.
This is used as a stream cipher , by xoring the stream emitted by it against the plaintext.

# Poly1305
I tried to optimise this but failed to do anything substantial!
This is used as intergrity check
Uses modulo arithmetic to calculate a hash type thing.

# CSPRNG
Just used the random stream given by chacha20 as a CSPRNG
CSPRNG means cryptographically secure prng!
They are supposed to have certain properties which you can look up!

# Warning
These implementations may not be secure against side channel attacks and may even be broken.Do not use these in production!

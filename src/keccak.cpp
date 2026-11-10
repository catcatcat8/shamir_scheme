// Keccak-256 (the pre-standard padding used by Ethereum).
// OpenSSL 3.0 only exposes SHA3-256, which uses different padding, so this is
// a small portable implementation of Keccak-f[1600]. It only hashes public
// data (public keys and addresses) and is checked against known test vectors.

#include "keccak.hpp"
#include "shamir_keys.hpp"

namespace shamir {

namespace {

constexpr std::uint64_t kRoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

constexpr unsigned kRotations[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                                     27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

constexpr unsigned kPiLanes[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                                   15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

constexpr std::size_t kRate = 136;  // (1600 - 2 * 256) / 8

std::uint64_t rotl(std::uint64_t value, unsigned shift) { return (value << shift) | (value >> (64 - shift)); }

void keccak_f(std::uint64_t state[25]) {
    std::uint64_t c[5];
    for (std::uint64_t round_constant : kRoundConstants) {
        // Theta
        for (int i = 0; i < 5; ++i) c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        for (int i = 0; i < 5; ++i) {
            const std::uint64_t t = c[(i + 4) % 5] ^ rotl(c[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) state[j + i] ^= t;
        }
        // Rho and Pi
        std::uint64_t current = state[1];
        for (int i = 0; i < 24; ++i) {
            const unsigned lane = kPiLanes[i];
            const std::uint64_t next = state[lane];
            state[lane] = rotl(current, kRotations[i]);
            current = next;
        }
        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; ++i) c[i] = state[j + i];
            for (int i = 0; i < 5; ++i) state[j + i] ^= (~c[(i + 1) % 5]) & c[(i + 2) % 5];
        }
        // Iota
        state[0] ^= round_constant;
    }
}

// Lanes are little-endian; byte-wise access keeps this independent of host endianness.
void xor_byte(std::uint64_t state[25], std::size_t index, std::uint8_t value) {
    state[index / 8] ^= static_cast<std::uint64_t>(value) << (8 * (index % 8));
}

}  // namespace

namespace internal {

std::array<std::uint8_t, 32> sponge256(const std::uint8_t* data, std::size_t size, std::uint8_t domain) {
    std::uint64_t state[25] = {};
    while (size >= kRate) {
        for (std::size_t i = 0; i < kRate; ++i) xor_byte(state, i, data[i]);
        keccak_f(state);
        data += kRate;
        size -= kRate;
    }
    for (std::size_t i = 0; i < size; ++i) xor_byte(state, i, data[i]);
    xor_byte(state, size, domain);
    xor_byte(state, kRate - 1, 0x80);
    keccak_f(state);

    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(state[i / 8] >> (8 * (i % 8)));
    return out;
}

}  // namespace internal

std::array<std::uint8_t, 32> keccak256(const std::uint8_t* data, std::size_t size) {
    return internal::sponge256(data, size, internal::kKeccakDomain);
}

}  // namespace shamir

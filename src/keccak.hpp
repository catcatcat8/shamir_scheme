// Internal: the Keccak[512] sponge with 256-bit output and a selectable
// domain-separation byte, so the same code can be tested as SHA3-256.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace shamir::internal {

inline constexpr std::uint8_t kKeccakDomain = 0x01;  // original Keccak (Ethereum)
inline constexpr std::uint8_t kSha3Domain = 0x06;    // FIPS 202 SHA3-256

std::array<std::uint8_t, 32> sponge256(const std::uint8_t* data, std::size_t size, std::uint8_t domain);

}  // namespace shamir::internal

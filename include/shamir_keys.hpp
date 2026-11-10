// secp256k1 private key helpers: generation, validation, public key and
// Ethereum address. Used by the CLI to show which key the shares belong to.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "shamir.hpp"

namespace shamir {

/// Size in bytes of an uncompressed secp256k1 point (0x04 || X || Y).
inline constexpr std::size_t kUncompressedPointSize = 65;

/// Returns a uniformly random private key in [1, n - 1].
Scalar generate_private_key();

/// Returns true if 1 <= key <= n - 1.
bool is_valid_private_key(const Scalar& key);

/// Throws `Error` unless 1 <= key <= n - 1.
void require_valid_private_key(const Scalar& key);

/// Returns key * G in uncompressed form.
std::array<std::uint8_t, kUncompressedPointSize> public_key(const Scalar& key);

/// Returns the EIP-55 checksummed Ethereum address of the key, with "0x".
std::string ethereum_address(const Scalar& key);

/// Keccak-256 as used by Ethereum (original Keccak padding, not SHA3-256).
std::array<std::uint8_t, 32> keccak256(const std::uint8_t* data, std::size_t size);

}  // namespace shamir

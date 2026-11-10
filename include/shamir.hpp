// Shamir's secret sharing over the scalar field of secp256k1,
// with optional Feldman verifiable secret sharing (VSS).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace shamir {

/// Size in bytes of a secp256k1 scalar (a field element modulo the group order n).
inline constexpr std::size_t kScalarSize = 32;

/// Size in bytes of a compressed secp256k1 point.
inline constexpr std::size_t kCompressedPointSize = 33;

/// Share x-coordinates are 1..255, so at most 255 shares can exist.
inline constexpr unsigned kMaxShares = 255;

/// Thrown on invalid input and on internal (OpenSSL) failures.
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/// Lowercase hex encoding.
std::string to_hex(const std::uint8_t* data, std::size_t size);

/// A 32-byte big-endian integer. Used for secrets, share values and
/// polynomial coefficients. The bytes are wiped when the object is destroyed.
class Scalar {
public:
    Scalar() = default;
    explicit Scalar(const std::array<std::uint8_t, kScalarSize>& bytes) : bytes_(bytes) {}
    Scalar(const Scalar&) = default;
    Scalar& operator=(const Scalar&) = default;
    ~Scalar();

    /// Parses 1..64 hex digits, with an optional "0x" prefix. Shorter input is
    /// left-padded with zeros. Does not check the value against the group order.
    static Scalar from_hex(std::string_view hex);

    /// Returns exactly 64 lowercase hex digits.
    std::string to_hex() const;

    const std::array<std::uint8_t, kScalarSize>& bytes() const { return bytes_; }

    /// Constant-time comparison.
    bool operator==(const Scalar& other) const;
    bool operator!=(const Scalar& other) const { return !(*this == other); }

private:
    std::array<std::uint8_t, kScalarSize> bytes_{};
};

/// One share: the point (x, f(x) mod n) on the secret polynomial.
struct Share {
    std::uint8_t x = 0;
    Scalar y;

    /// Text form "x:y", where x is decimal (1..255) and y is 64 hex digits.
    std::string to_string() const;
    static Share from_string(std::string_view text);
};

/// Feldman commitments C_j = a_j * G to the polynomial coefficients.
/// C_0 = secret * G is the public key of the shared secret.
/// The number of commitments equals the threshold.
struct Commitments {
    std::vector<std::array<std::uint8_t, kCompressedPointSize>> points;

    std::size_t threshold() const { return points.size(); }

    /// Text form: compressed points as hex, separated by commas.
    std::string to_string() const;
    static Commitments from_string(std::string_view text);
};

struct VerifiableSplit {
    std::vector<Share> shares;
    Commitments commitments;
};

/// Splits `secret` into `count` shares so that any `threshold` of them
/// recover it and fewer reveal nothing about it.
///
/// Requires 1 <= threshold <= count <= 255 and 1 <= secret <= n - 1.
/// Coefficients a_1..a_{t-1} are drawn from OpenSSL's CSPRNG in [1, n - 1].
std::vector<Share> split(const Scalar& secret, unsigned threshold, unsigned count);

/// Recovers f(0) from the given shares with Lagrange interpolation mod n.
///
/// The shares must have distinct non-zero x and y < n. The function cannot
/// know the threshold: with fewer than `threshold` shares, or with a corrupted
/// share, it returns a wrong value without an error. Use `combine_verified`
/// when commitments are available.
Scalar combine(const std::vector<Share>& shares);

/// Same as `split`, and also returns Feldman commitments to the coefficients.
VerifiableSplit split_verifiable(const Scalar& secret, unsigned threshold, unsigned count);

/// Checks y * G == sum_j C_j * x^j. Returns false for a share that does not
/// lie on the committed polynomial. Throws on malformed commitments.
bool verify_share(const Share& share, const Commitments& commitments);

/// Verifies every share against the commitments, then combines them.
/// Throws if a share is invalid or if fewer than `threshold` shares are given.
Scalar combine_verified(const std::vector<Share>& shares, const Commitments& commitments);

namespace detail {

/// Evaluates the polynomial with the given coefficients (coefficients[0] is
/// the secret) at x = 1..count. No validation of the secret as a private key.
/// Exposed for known-answer tests.
std::vector<Share> evaluate(const std::vector<Scalar>& coefficients, unsigned count);

/// Computes C_j = a_j * G. Every coefficient must be in [1, n - 1].
Commitments commit(const std::vector<Scalar>& coefficients);

}  // namespace detail

}  // namespace shamir

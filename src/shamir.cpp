// Shamir's secret sharing in the prime field Z_n, where n is the order of the
// secp256k1 group. All arithmetic is modular; there is no floating point.
//
//   split:   f(x) = a_0 + a_1 x + ... + a_{t-1} x^{t-1}  (mod n),  a_0 = secret
//            share_i = (i, f(i)),  i = 1..N
//   combine: f(0) = sum_i y_i * prod_{j != i} x_j / (x_j - x_i)  (mod n)
//   Feldman: C_j = a_j G,  share is valid iff  y G == sum_j x^j C_j

#include "shamir.hpp"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <algorithm>
#include <bitset>

#include "openssl_util.hpp"
#include "shamir_keys.hpp"

namespace shamir {

using internal::BnPtr;
using internal::check;
using internal::PointPtr;

// ---------------------------------------------------------------------------
// Hex and text encoding
// ---------------------------------------------------------------------------

namespace {

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decodes exactly `out_size * 2` hex digits into `out`.
void decode_hex(std::string_view hex, std::uint8_t* out, std::size_t out_size) {
    if (hex.size() != out_size * 2) throw Error("invalid hex length");
    for (std::size_t i = 0; i < out_size; ++i) {
        const int hi = hex_value(hex[2 * i]);
        const int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) throw Error("invalid hex digit");
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
}

}  // namespace

std::string to_hex(const std::uint8_t* data, std::size_t size) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

Scalar::~Scalar() { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }

Scalar Scalar::from_hex(std::string_view hex) {
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex.remove_prefix(2);
    if (hex.empty() || hex.size() > kScalarSize * 2) {
        throw Error("scalar must have 1 to 64 hex digits");
    }
    std::string padded(kScalarSize * 2 - hex.size(), '0');
    padded.append(hex);
    std::array<std::uint8_t, kScalarSize> bytes{};
    try {
        decode_hex(padded, bytes.data(), bytes.size());
    } catch (...) {
        OPENSSL_cleanse(padded.data(), padded.size());
        throw;
    }
    OPENSSL_cleanse(padded.data(), padded.size());
    Scalar result(bytes);
    OPENSSL_cleanse(bytes.data(), bytes.size());
    return result;
}

std::string Scalar::to_hex() const { return shamir::to_hex(bytes_.data(), bytes_.size()); }

bool Scalar::operator==(const Scalar& other) const {
    return CRYPTO_memcmp(bytes_.data(), other.bytes_.data(), kScalarSize) == 0;
}

std::string Share::to_string() const { return std::to_string(x) + ":" + y.to_hex(); }

Share Share::from_string(std::string_view text) {
    const std::size_t colon = text.find(':');
    if (colon == std::string_view::npos) throw Error("share must have the form x:y");
    const std::string_view x_text = text.substr(0, colon);
    if (x_text.empty() || x_text.size() > 3 ||
        !std::all_of(x_text.begin(), x_text.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        throw Error("share x must be a decimal number from 1 to 255");
    }
    unsigned x = 0;
    for (char c : x_text) x = x * 10 + static_cast<unsigned>(c - '0');
    if (x < 1 || x > kMaxShares) throw Error("share x must be a decimal number from 1 to 255");

    Share share;
    share.x = static_cast<std::uint8_t>(x);
    share.y = Scalar::from_hex(text.substr(colon + 1));
    return share;
}

std::string Commitments::to_string() const {
    std::string out;
    for (std::size_t i = 0; i < points.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += to_hex(points[i].data(), points[i].size());
    }
    return out;
}

Commitments Commitments::from_string(std::string_view text) {
    Commitments result;
    while (true) {
        const std::size_t comma = text.find(',');
        const std::string_view item = text.substr(0, comma);
        std::array<std::uint8_t, kCompressedPointSize> point{};
        try {
            decode_hex(item, point.data(), point.size());
        } catch (const Error&) {
            throw Error("each commitment must be a compressed point (66 hex digits)");
        }
        result.points.push_back(point);
        if (result.points.size() > kMaxShares) throw Error("too many commitments");
        if (comma == std::string_view::npos) break;
        text.remove_prefix(comma + 1);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Splitting and combining
// ---------------------------------------------------------------------------

namespace {

void require_split_parameters(unsigned threshold, unsigned count) {
    if (threshold < 1) throw Error("threshold must be at least 1");
    if (count > kMaxShares) throw Error("share count must be at most 255");
    if (threshold > count) throw Error("threshold must not exceed the share count");
}

// a_0 = secret, a_1..a_{t-1} uniformly random in [1, n - 1]. Excluding zero
// keeps the polynomial at full degree and keeps every Feldman commitment a
// regular point; the bias this adds is 1/n per coefficient.
std::vector<Scalar> make_coefficients(const Scalar& secret, unsigned threshold) {
    require_valid_private_key(secret);
    std::vector<Scalar> coefficients;
    coefficients.reserve(threshold);
    coefficients.push_back(secret);

    BnPtr n_minus_one = internal::new_bn();
    check(BN_sub(n_minus_one.get(), internal::order(), BN_value_one()), "BN_sub");
    BnPtr value = internal::new_bn();
    for (unsigned j = 1; j < threshold; ++j) {
        check(BN_priv_rand_range(value.get(), n_minus_one.get()), "BN_priv_rand_range");  // [0, n-2]
        check(BN_add_word(value.get(), 1), "BN_add_word");                                // [1, n-1]
        coefficients.push_back(internal::scalar_from_bn(value.get()));
    }
    return coefficients;
}

std::vector<PointPtr> decode_commitments(const Commitments& commitments) {
    if (commitments.points.empty()) throw Error("commitments are empty");
    if (commitments.points.size() > kMaxShares) throw Error("too many commitments");
    auto ctx = internal::new_ctx();
    std::vector<PointPtr> points;
    points.reserve(commitments.points.size());
    for (const auto& encoded : commitments.points) {
        PointPtr point = internal::new_point();
        // oct2point rejects encodings that are not on the curve.
        if (EC_POINT_oct2point(internal::curve(), point.get(), encoded.data(), encoded.size(), ctx.get()) != 1 ||
            EC_POINT_is_at_infinity(internal::curve(), point.get()) == 1) {
            throw Error("commitment is not a valid secp256k1 point");
        }
        points.push_back(std::move(point));
    }
    return points;
}

bool verify_share_against(const Share& share, const std::vector<PointPtr>& points) {
    if (share.x == 0 || !internal::less_than_order(share.y)) return false;
    const EC_GROUP* group = internal::curve();
    auto ctx = internal::new_ctx();

    // Left side: y * G.
    BnPtr y = internal::bn_from_scalar(share.y);
    PointPtr lhs = internal::new_point();
    check(EC_POINT_mul(group, lhs.get(), y.get(), nullptr, nullptr, ctx.get()), "EC_POINT_mul");

    // Right side: sum_j x^j C_j, evaluated with Horner's rule.
    BnPtr x = internal::bn_from_uint(share.x);
    PointPtr acc(EC_POINT_dup(points.back().get(), group));
    if (!acc) throw Error("EC_POINT_dup failed");
    PointPtr scaled = internal::new_point();
    for (std::size_t j = points.size() - 1; j-- > 0;) {
        check(EC_POINT_mul(group, scaled.get(), nullptr, acc.get(), x.get(), ctx.get()), "EC_POINT_mul");
        check(EC_POINT_add(group, acc.get(), scaled.get(), points[j].get(), ctx.get()), "EC_POINT_add");
    }

    const int cmp = EC_POINT_cmp(group, lhs.get(), acc.get(), ctx.get());
    if (cmp < 0) check(0, "EC_POINT_cmp");
    return cmp == 0;
}

}  // namespace

namespace detail {

std::vector<Share> evaluate(const std::vector<Scalar>& coefficients, unsigned count) {
    const auto threshold = static_cast<unsigned>(std::min<std::size_t>(coefficients.size(), kMaxShares + 1));
    require_split_parameters(threshold, count);

    const BIGNUM* n = internal::order();
    auto ctx = internal::new_ctx();
    std::vector<BnPtr> a;
    a.reserve(coefficients.size());
    for (const Scalar& c : coefficients) {
        if (!internal::less_than_order(c)) throw Error("coefficient must be less than the group order");
        a.push_back(internal::bn_from_scalar(c));
    }

    std::vector<Share> shares;
    shares.reserve(count);
    BnPtr acc = internal::new_bn();
    for (unsigned i = 1; i <= count; ++i) {
        BnPtr x = internal::bn_from_uint(i);
        // Horner: f(x) = (...(a_{t-1} x + a_{t-2}) x + ...) x + a_0  (mod n)
        if (BN_copy(acc.get(), a.back().get()) == nullptr) check(0, "BN_copy");
        for (std::size_t j = a.size() - 1; j-- > 0;) {
            check(BN_mod_mul(acc.get(), acc.get(), x.get(), n, ctx.get()), "BN_mod_mul");
            check(BN_mod_add(acc.get(), acc.get(), a[j].get(), n, ctx.get()), "BN_mod_add");
        }
        shares.push_back(Share{static_cast<std::uint8_t>(i), internal::scalar_from_bn(acc.get())});
    }
    return shares;
}

Commitments commit(const std::vector<Scalar>& coefficients) {
    const EC_GROUP* group = internal::curve();
    auto ctx = internal::new_ctx();
    Commitments result;
    result.points.reserve(coefficients.size());
    PointPtr point = internal::new_point();
    for (const Scalar& c : coefficients) {
        if (!is_valid_private_key(c)) throw Error("coefficient must be in [1, n - 1]");
        BnPtr a = internal::bn_from_scalar(c);
        check(EC_POINT_mul(group, point.get(), a.get(), nullptr, nullptr, ctx.get()), "EC_POINT_mul");
        std::array<std::uint8_t, kCompressedPointSize> encoded{};
        if (EC_POINT_point2oct(group, point.get(), POINT_CONVERSION_COMPRESSED, encoded.data(), encoded.size(),
                               ctx.get()) != encoded.size()) {
            throw Error("EC_POINT_point2oct failed");
        }
        result.points.push_back(encoded);
    }
    return result;
}

}  // namespace detail

std::vector<Share> split(const Scalar& secret, unsigned threshold, unsigned count) {
    require_split_parameters(threshold, count);
    return detail::evaluate(make_coefficients(secret, threshold), count);
}

VerifiableSplit split_verifiable(const Scalar& secret, unsigned threshold, unsigned count) {
    require_split_parameters(threshold, count);
    const std::vector<Scalar> coefficients = make_coefficients(secret, threshold);
    return VerifiableSplit{detail::evaluate(coefficients, count), detail::commit(coefficients)};
}

Scalar combine(const std::vector<Share>& shares) {
    if (shares.empty()) throw Error("at least one share is required");
    if (shares.size() > kMaxShares) throw Error("too many shares");

    std::bitset<kMaxShares + 1> seen;
    for (const Share& share : shares) {
        if (share.x == 0) throw Error("share x must not be 0");
        if (seen.test(share.x)) throw Error("duplicate share x = " + std::to_string(share.x));
        seen.set(share.x);
        if (!internal::less_than_order(share.y)) throw Error("share y must be less than the group order");
    }

    const BIGNUM* n = internal::order();
    auto ctx = internal::new_ctx();
    BnPtr secret = internal::new_bn();
    BN_zero(secret.get());
    BnPtr numerator = internal::new_bn();
    BnPtr denominator = internal::new_bn();
    BnPtr difference = internal::new_bn();
    BnPtr term = internal::new_bn();

    for (std::size_t i = 0; i < shares.size(); ++i) {
        // Lagrange basis polynomial at 0: lambda_i = prod_{j != i} x_j / (x_j - x_i).
        // It depends only on the public x values.
        check(BN_one(numerator.get()), "BN_one");
        check(BN_one(denominator.get()), "BN_one");
        BnPtr x_i = internal::bn_from_uint(shares[i].x);
        for (std::size_t j = 0; j < shares.size(); ++j) {
            if (j == i) continue;
            BnPtr x_j = internal::bn_from_uint(shares[j].x);
            check(BN_mod_mul(numerator.get(), numerator.get(), x_j.get(), n, ctx.get()), "BN_mod_mul");
            check(BN_mod_sub(difference.get(), x_j.get(), x_i.get(), n, ctx.get()), "BN_mod_sub");
            check(BN_mod_mul(denominator.get(), denominator.get(), difference.get(), n, ctx.get()), "BN_mod_mul");
        }
        // n is prime and the x values are distinct, so the denominator is invertible.
        if (BN_mod_inverse(denominator.get(), denominator.get(), n, ctx.get()) == nullptr) check(0, "BN_mod_inverse");
        check(BN_mod_mul(term.get(), numerator.get(), denominator.get(), n, ctx.get()), "BN_mod_mul");

        // secret += lambda_i * y_i
        BnPtr y_i = internal::bn_from_scalar(shares[i].y);
        check(BN_mod_mul(term.get(), term.get(), y_i.get(), n, ctx.get()), "BN_mod_mul");
        check(BN_mod_add(secret.get(), secret.get(), term.get(), n, ctx.get()), "BN_mod_add");
    }
    return internal::scalar_from_bn(secret.get());
}

bool verify_share(const Share& share, const Commitments& commitments) {
    return verify_share_against(share, decode_commitments(commitments));
}

Scalar combine_verified(const std::vector<Share>& shares, const Commitments& commitments) {
    const std::vector<PointPtr> points = decode_commitments(commitments);
    if (shares.size() < points.size()) {
        throw Error("need at least " + std::to_string(points.size()) + " shares, got " +
                    std::to_string(shares.size()));
    }
    for (const Share& share : shares) {
        if (!verify_share_against(share, points)) {
            throw Error("share x = " + std::to_string(share.x) + " does not match the commitments");
        }
    }
    Scalar secret = combine(shares);

    // Defense in depth: the result must be the discrete log of C_0.
    const auto expected = detail::commit({secret});
    if (CRYPTO_memcmp(expected.points[0].data(), commitments.points[0].data(), kCompressedPointSize) != 0) {
        throw Error("recovered secret does not match commitment C_0");
    }
    return secret;
}

}  // namespace shamir

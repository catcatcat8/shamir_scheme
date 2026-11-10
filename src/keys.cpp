#include "shamir_keys.hpp"

#include <openssl/crypto.h>

#include <cctype>

#include "openssl_util.hpp"

namespace shamir {

using internal::BnPtr;
using internal::check;

Scalar generate_private_key() {
    BnPtr n_minus_one = internal::new_bn();
    check(BN_sub(n_minus_one.get(), internal::order(), BN_value_one()), "BN_sub");
    BnPtr key = internal::new_bn();
    check(BN_priv_rand_range(key.get(), n_minus_one.get()), "BN_priv_rand_range");  // [0, n-2]
    check(BN_add_word(key.get(), 1), "BN_add_word");                                // [1, n-1]
    return internal::scalar_from_bn(key.get());
}

bool is_valid_private_key(const Scalar& key) {
    BnPtr bn = internal::bn_from_scalar(key);
    return !BN_is_zero(bn.get()) && BN_cmp(bn.get(), internal::order()) < 0;
}

void require_valid_private_key(const Scalar& key) {
    if (!is_valid_private_key(key)) {
        throw Error("private key must be in [1, n - 1], where n is the secp256k1 group order");
    }
}

std::array<std::uint8_t, kUncompressedPointSize> public_key(const Scalar& key) {
    require_valid_private_key(key);
    const EC_GROUP* group = internal::curve();
    auto ctx = internal::new_ctx();
    BnPtr k = internal::bn_from_scalar(key);
    internal::PointPtr point = internal::new_point();
    check(EC_POINT_mul(group, point.get(), k.get(), nullptr, nullptr, ctx.get()), "EC_POINT_mul");
    std::array<std::uint8_t, kUncompressedPointSize> out{};
    if (EC_POINT_point2oct(group, point.get(), POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), ctx.get()) !=
        out.size()) {
        throw Error("EC_POINT_point2oct failed");
    }
    return out;
}

std::string ethereum_address(const Scalar& key) {
    const auto pub = public_key(key);
    // Address = last 20 bytes of keccak256(X || Y), without the 0x04 prefix.
    const auto hash = keccak256(pub.data() + 1, pub.size() - 1);
    const std::string lower = to_hex(hash.data() + 12, 20);

    // EIP-55: uppercase a letter if the matching nibble of keccak256(lower) is >= 8.
    const auto checksum = keccak256(reinterpret_cast<const std::uint8_t*>(lower.data()), lower.size());
    std::string address = "0x";
    for (std::size_t i = 0; i < lower.size(); ++i) {
        const std::uint8_t nibble = (i % 2 == 0) ? (checksum[i / 2] >> 4) : (checksum[i / 2] & 0x0f);
        const char c = lower[i];
        address.push_back(nibble >= 8 ? static_cast<char>(std::toupper(static_cast<unsigned char>(c))) : c);
    }
    return address;
}

}  // namespace shamir

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include <string>
#include <vector>

#include "../src/keccak.hpp"
#include "shamir_keys.hpp"
#include "test_util.hpp"

namespace shamir {
namespace {

using test::small;

std::string keccak_hex(const std::string& input) {
    const auto hash = keccak256(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
    return to_hex(hash.data(), hash.size());
}

TEST(Keccak, KnownVectors) {
    EXPECT_EQ(keccak_hex(""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    EXPECT_EQ(keccak_hex("abc"), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    EXPECT_EQ(keccak_hex("The quick brown fox jumps over the lazy dog"),
              "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15");
}

// Keccak-256 and SHA3-256 share the sponge and differ only in the padding
// byte. Comparing the SHA3 variant against OpenSSL checks the permutation and
// multi-block absorption for every length around the 136-byte block size.
TEST(Keccak, SpongeMatchesOpenSslSha3) {
    std::vector<std::uint8_t> data(3 * 136 + 5);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i * 7 + 3);
    for (std::size_t size = 0; size <= data.size(); ++size) {
        std::uint8_t expected[32];
        unsigned int length = 0;
        ASSERT_EQ(EVP_Digest(data.data(), size, expected, &length, EVP_sha3_256(), nullptr), 1);
        const auto actual = internal::sponge256(data.data(), size, internal::kSha3Domain);
        ASSERT_EQ(to_hex(actual.data(), actual.size()), to_hex(expected, length)) << "size " << size;
    }
}

TEST(Keys, PublicKeyOfOneIsTheGenerator) {
    const auto pub = public_key(small(1));
    EXPECT_EQ(to_hex(pub.data(), pub.size()),
              "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
}

TEST(Keys, KnownEthereumAddresses) {
    EXPECT_EQ(ethereum_address(small(1)), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    EXPECT_EQ(ethereum_address(small(2)), "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF");
}

TEST(Keys, ValidityBoundaries) {
    EXPECT_FALSE(is_valid_private_key(small(0)));
    EXPECT_TRUE(is_valid_private_key(small(1)));
    EXPECT_TRUE(is_valid_private_key(Scalar::from_hex(test::kOrderMinusOneHex)));
    EXPECT_FALSE(is_valid_private_key(Scalar::from_hex(test::kOrderHex)));
    EXPECT_FALSE(is_valid_private_key(Scalar::from_hex(std::string(64, 'f'))));
    EXPECT_THROW(public_key(small(0)), Error);
}

TEST(Keys, GeneratedKeysAreValidAndDistinct) {
    const Scalar a = generate_private_key();
    const Scalar b = generate_private_key();
    EXPECT_TRUE(is_valid_private_key(a));
    EXPECT_TRUE(is_valid_private_key(b));
    EXPECT_NE(a, b);
}

}  // namespace
}  // namespace shamir

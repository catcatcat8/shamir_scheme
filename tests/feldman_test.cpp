#include <gtest/gtest.h>

#include "shamir.hpp"
#include "shamir_keys.hpp"
#include "test_util.hpp"

namespace shamir {
namespace {

using test::combinations;
using test::pick;
using test::small;

// Compressed encoding of the secp256k1 generator G.
const std::string kGeneratorCompressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

TEST(Feldman, CommitmentOfOneIsTheGenerator) {
    EXPECT_EQ(detail::commit({small(1)}).to_string(), kGeneratorCompressed);
}

TEST(Feldman, CommitmentsRejectZeroCoefficient) { EXPECT_THROW(detail::commit({small(1), small(0)}), Error); }

TEST(Feldman, FirstCommitmentIsThePublicKey) {
    const Scalar secret = generate_private_key();
    const auto result = split_verifiable(secret, 3, 5);
    ASSERT_EQ(result.commitments.threshold(), 3u);

    const auto pub = public_key(secret);  // 04 || X || Y
    const auto& c0 = result.commitments.points[0];
    EXPECT_EQ(c0[0], (pub[64] & 1) ? 0x03 : 0x02);
    EXPECT_TRUE(std::equal(c0.begin() + 1, c0.end(), pub.begin() + 1));
}

TEST(Feldman, AllSharesVerify) {
    const auto result = split_verifiable(generate_private_key(), 3, 10);
    for (const auto& share : result.shares) EXPECT_TRUE(verify_share(share, result.commitments));
}

TEST(Feldman, TamperedShareValueFails) {
    const auto result = split_verifiable(generate_private_key(), 3, 5);
    Share share = result.shares[2];
    auto bytes = share.y.bytes();
    bytes[31] ^= 0x01;
    share.y = Scalar(bytes);
    EXPECT_FALSE(verify_share(share, result.commitments));
}

TEST(Feldman, ShareWithWrongIndexFails) {
    const auto result = split_verifiable(generate_private_key(), 3, 5);
    Share share = result.shares[0];
    share.x = 2;
    EXPECT_FALSE(verify_share(share, result.commitments));
}

TEST(Feldman, ShareFromAnotherSplitFails) {
    const Scalar secret = generate_private_key();
    const auto a = split_verifiable(secret, 3, 5);
    const auto b = split_verifiable(secret, 3, 5);  // same secret, other coefficients
    EXPECT_FALSE(verify_share(b.shares[0], a.commitments));
}

TEST(Feldman, ShareOutsideFieldFails) {
    const auto result = split_verifiable(generate_private_key(), 2, 3);
    Share share = result.shares[0];
    share.y = Scalar::from_hex(test::kOrderHex);
    EXPECT_FALSE(verify_share(share, result.commitments));
}

TEST(Feldman, CombineVerifiedRecoversFromAnyThresholdSubset) {
    const Scalar secret = generate_private_key();
    const auto result = split_verifiable(secret, 3, 5);
    for (const auto& subset : combinations(5, 3)) {
        EXPECT_EQ(combine_verified(pick(result.shares, subset), result.commitments), secret);
    }
    EXPECT_EQ(combine_verified(result.shares, result.commitments), secret);
}

TEST(Feldman, CombineVerifiedRejectsTooFewShares) {
    const auto result = split_verifiable(generate_private_key(), 3, 5);
    EXPECT_THROW(combine_verified({result.shares[0], result.shares[1]}, result.commitments), Error);
}

TEST(Feldman, CombineVerifiedRejectsCorruptedShare) {
    const auto result = split_verifiable(generate_private_key(), 3, 5);
    auto shares = pick(result.shares, {0, 1, 2});
    auto bytes = shares[1].y.bytes();
    bytes[0] ^= 0x80;
    shares[1].y = Scalar(bytes);
    EXPECT_THROW(combine_verified(shares, result.commitments), Error);
}

TEST(Feldman, ThresholdOneAndMaximumShares) {
    const Scalar secret = generate_private_key();
    const auto one = split_verifiable(secret, 1, 3);
    EXPECT_EQ(combine_verified({one.shares[2]}, one.commitments), secret);

    const auto many = split_verifiable(secret, 3, 255);
    for (std::size_t i = 0; i < many.shares.size(); i += 17) EXPECT_TRUE(verify_share(many.shares[i], many.commitments));
    EXPECT_EQ(combine_verified({many.shares[254], many.shares[7], many.shares[100]}, many.commitments), secret);
}

TEST(Feldman, CommitmentsRoundTrip) {
    const auto result = split_verifiable(generate_private_key(), 4, 4);
    const auto parsed = Commitments::from_string(result.commitments.to_string());
    EXPECT_EQ(parsed.points, result.commitments.points);
}

TEST(Feldman, RejectsMalformedCommitments) {
    EXPECT_THROW(Commitments::from_string(""), Error);
    EXPECT_THROW(Commitments::from_string(kGeneratorCompressed + ","), Error);
    EXPECT_THROW(Commitments::from_string(kGeneratorCompressed.substr(2)), Error);

    const Share share = Share::from_string("1:1");
    // x = 2^256 - 1 is larger than the field prime, so this is not a point.
    const auto not_on_curve = Commitments::from_string("02" + std::string(64, 'f'));
    EXPECT_THROW(verify_share(share, not_on_curve), Error);
    // Invalid prefix byte.
    const auto bad_prefix = Commitments::from_string("05" + kGeneratorCompressed.substr(2));
    EXPECT_THROW(verify_share(share, bad_prefix), Error);
    EXPECT_THROW(verify_share(share, Commitments{}), Error);
}

}  // namespace
}  // namespace shamir

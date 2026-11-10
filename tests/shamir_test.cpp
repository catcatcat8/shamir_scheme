#include <gtest/gtest.h>

#include <random>
#include <set>

#include "shamir.hpp"
#include "shamir_keys.hpp"
#include "test_util.hpp"

namespace shamir {
namespace {

using test::combinations;
using test::kOrderHex;
using test::kOrderMinusOneHex;
using test::pick;
using test::small;

// ---------------------------------------------------------------------------
// Known answers
// ---------------------------------------------------------------------------

TEST(Evaluate, KnownPolynomial) {
    // f(x) = 1 + 2x + 3x^2  ->  f(1) = 6, f(2) = 17, f(3) = 34
    const auto shares = detail::evaluate({small(1), small(2), small(3)}, 3);
    ASSERT_EQ(shares.size(), 3u);
    EXPECT_EQ(shares[0].to_string(), "1:" + std::string(63, '0') + "6");
    EXPECT_EQ(shares[1].to_string(), "2:" + std::string(62, '0') + "11");
    EXPECT_EQ(shares[2].to_string(), "3:" + std::string(62, '0') + "22");
    EXPECT_EQ(combine(shares), small(1));
}

TEST(Evaluate, ReducesModuloGroupOrder) {
    // f(x) = (n - 1) + x  ->  f(1) = n = 0 (mod n), f(2) = n + 1 = 1 (mod n)
    const auto shares = detail::evaluate({Scalar::from_hex(kOrderMinusOneHex), small(1)}, 2);
    EXPECT_EQ(shares[0].y, small(0));
    EXPECT_EQ(shares[1].y, small(1));
    EXPECT_EQ(combine(shares), Scalar::from_hex(kOrderMinusOneHex));
}

TEST(Evaluate, RejectsCoefficientNotBelowOrder) {
    EXPECT_THROW(detail::evaluate({small(1), Scalar::from_hex(kOrderHex)}, 2), Error);
}

TEST(Combine, KnownSharesInAnyOrder) {
    const std::vector<Share> shares = {Share::from_string("3:22"), Share::from_string("1:6"),
                                       Share::from_string("2:11")};
    EXPECT_EQ(combine(shares), small(1));
}

// ---------------------------------------------------------------------------
// Recovery from subsets
// ---------------------------------------------------------------------------

TEST(Split, EveryThresholdSubsetRecoversTheSameSecret) {
    const Scalar secret = generate_private_key();
    const auto shares = split(secret, 3, 5);
    for (const auto& subset : combinations(5, 3)) {
        auto chosen = pick(shares, subset);
        EXPECT_EQ(combine(chosen), secret);
        std::reverse(chosen.begin(), chosen.end());
        EXPECT_EQ(combine(chosen), secret);
    }
}

TEST(Split, MoreThanThresholdSharesRecover) {
    const Scalar secret = generate_private_key();
    const auto shares = split(secret, 3, 7);
    for (std::size_t k = 3; k <= 7; ++k) {
        for (const auto& subset : combinations(7, k)) EXPECT_EQ(combine(pick(shares, subset)), secret);
    }
}

TEST(Split, FewerThanThresholdSharesDoNotRecover) {
    const Scalar secret = generate_private_key();
    const auto shares = split(secret, 4, 6);
    for (std::size_t k = 1; k < 4; ++k) {
        for (const auto& subset : combinations(6, k)) EXPECT_NE(combine(pick(shares, subset)), secret);
    }
}

TEST(Split, SharesHaveSequentialXAndValuesBelowOrder) {
    const auto shares = split(generate_private_key(), 2, 10);
    ASSERT_EQ(shares.size(), 10u);
    for (std::size_t i = 0; i < shares.size(); ++i) {
        EXPECT_EQ(shares[i].x, i + 1);
        EXPECT_NE(shares[i].y.to_hex(), Scalar::from_hex(kOrderHex).to_hex());
    }
}

TEST(Split, UsesFreshRandomnessEachTime) {
    const Scalar secret = generate_private_key();
    const auto a = split(secret, 2, 3);
    const auto b = split(secret, 2, 3);
    for (std::size_t i = 0; i < a.size(); ++i) EXPECT_NE(a[i].y, b[i].y);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

TEST(Split, ThresholdOneMakesEveryShareTheSecret) {
    const Scalar secret = generate_private_key();
    for (const auto& share : split(secret, 1, 4)) {
        EXPECT_EQ(share.y, secret);
        EXPECT_EQ(combine({share}), secret);
    }
}

TEST(Split, ThresholdEqualsShareCount) {
    const Scalar secret = generate_private_key();
    const auto shares = split(secret, 5, 5);
    EXPECT_EQ(combine(shares), secret);
    for (const auto& subset : combinations(5, 4)) EXPECT_NE(combine(pick(shares, subset)), secret);
}

TEST(Split, MaximumShareCount) {
    const Scalar secret = generate_private_key();
    const auto shares = split(secret, 255, 255);
    ASSERT_EQ(shares.size(), 255u);
    EXPECT_EQ(shares.back().x, 255);
    EXPECT_EQ(combine(shares), secret);

    std::vector<Share> missing_one(shares.begin() + 1, shares.end());
    EXPECT_NE(combine(missing_one), secret);
}

TEST(Split, SmallThresholdWithMaximumShares) {
    const Scalar secret = generate_private_key();
    const auto shares = split(secret, 2, 255);
    EXPECT_EQ(combine({shares[254], shares[0]}), secret);
    EXPECT_EQ(combine({shares[100], shares[200]}), secret);
}

TEST(Split, BoundarySecrets) {
    for (const Scalar& secret : {small(1), Scalar::from_hex(kOrderMinusOneHex)}) {
        const auto shares = split(secret, 3, 4);
        EXPECT_EQ(combine({shares[0], shares[2], shares[3]}), secret);
    }
}

// ---------------------------------------------------------------------------
// Invalid input
// ---------------------------------------------------------------------------

TEST(Split, RejectsInvalidParameters) {
    const Scalar secret = generate_private_key();
    EXPECT_THROW(split(secret, 0, 5), Error);
    EXPECT_THROW(split(secret, 6, 5), Error);
    EXPECT_THROW(split(secret, 1, 0), Error);
    EXPECT_THROW(split(secret, 2, 256), Error);
    EXPECT_THROW(split(secret, 256, 256), Error);
}

TEST(Split, RejectsInvalidSecrets) {
    EXPECT_THROW(split(small(0), 2, 3), Error);
    EXPECT_THROW(split(Scalar::from_hex(kOrderHex), 2, 3), Error);
    EXPECT_THROW(split(Scalar::from_hex(std::string(64, 'f')), 2, 3), Error);
}

TEST(Combine, RejectsInvalidShares) {
    EXPECT_THROW(combine({}), Error);

    const auto shares = split(generate_private_key(), 2, 3);
    EXPECT_THROW(combine({shares[0], shares[0]}), Error);

    Share zero_x = shares[0];
    zero_x.x = 0;
    EXPECT_THROW(combine({zero_x, shares[1]}), Error);

    Share big_y = shares[0];
    big_y.y = Scalar::from_hex(kOrderHex);
    EXPECT_THROW(combine({big_y, shares[1]}), Error);
}

TEST(Encoding, ShareRoundTrip) {
    for (const auto& share : split(generate_private_key(), 3, 255)) {
        const Share parsed = Share::from_string(share.to_string());
        EXPECT_EQ(parsed.x, share.x);
        EXPECT_EQ(parsed.y, share.y);
    }
}

TEST(Encoding, RejectsMalformedShares) {
    const std::string y(64, 'a');
    for (const std::string& text : {std::string(""), std::string("1"), ":" + y, "0:" + y, "256:" + y,
                                    "1000:" + y, "-1:" + y, "1a:" + y, " 1:" + y, std::string("1:"),
                                    std::string("1:0x"), std::string("1:zz"), "1:" + y + "a"}) {
        EXPECT_THROW(Share::from_string(text), Error) << "input: " << text;
    }
}

TEST(Encoding, ScalarHex) {
    EXPECT_EQ(Scalar::from_hex("0x1"), small(1));
    EXPECT_EQ(Scalar::from_hex("0X0001"), small(1));
    EXPECT_EQ(Scalar::from_hex("ABCDEF").to_hex(), std::string(58, '0') + "abcdef");
    EXPECT_THROW(Scalar::from_hex(""), Error);
    EXPECT_THROW(Scalar::from_hex("0x"), Error);
    EXPECT_THROW(Scalar::from_hex("g"), Error);
    EXPECT_THROW(Scalar::from_hex(std::string(65, '1')), Error);
}

// ---------------------------------------------------------------------------
// Property test
// ---------------------------------------------------------------------------

TEST(Property, ThousandRandomKeysRecoverFromRandomSubsets) {
    std::mt19937 rng(20201018);  // Only picks parameters and subsets; keys come from the CSPRNG.
    for (int iteration = 0; iteration < 1000; ++iteration) {
        const Scalar secret = generate_private_key();
        const unsigned count = std::uniform_int_distribution<unsigned>(1, 12)(rng);
        const unsigned threshold = std::uniform_int_distribution<unsigned>(1, count)(rng);
        auto shares = split(secret, threshold, count);
        std::shuffle(shares.begin(), shares.end(), rng);

        const std::vector<Share> enough(shares.begin(), shares.begin() + threshold);
        ASSERT_EQ(combine(enough), secret) << "t=" << threshold << " n=" << count;

        if (threshold > 1) {
            const std::vector<Share> too_few(shares.begin(), shares.begin() + threshold - 1);
            ASSERT_NE(combine(too_few), secret) << "t=" << threshold << " n=" << count;
        }
    }
}

}  // namespace
}  // namespace shamir

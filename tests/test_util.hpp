#pragma once

#include <algorithm>
#include <random>
#include <string>
#include <vector>

#include "shamir.hpp"

namespace shamir::test {

// Order of the secp256k1 group.
inline const std::string kOrderHex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
inline const std::string kOrderMinusOneHex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";

// Decimal digits are valid hex digits; this helper is only used with values < 10.
inline Scalar small(unsigned value) { return Scalar::from_hex(std::string(1, static_cast<char>('0' + value))); }

// All subsets of {0..n-1} with exactly k elements.
inline std::vector<std::vector<std::size_t>> combinations(std::size_t n, std::size_t k) {
    std::vector<std::vector<std::size_t>> result;
    std::vector<bool> mask(n, false);
    std::fill(mask.begin(), mask.begin() + static_cast<std::ptrdiff_t>(k), true);
    do {
        std::vector<std::size_t> subset;
        for (std::size_t i = 0; i < n; ++i)
            if (mask[i]) subset.push_back(i);
        result.push_back(subset);
    } while (std::prev_permutation(mask.begin(), mask.end()));
    return result;
}

inline std::vector<Share> pick(const std::vector<Share>& shares, const std::vector<std::size_t>& indices) {
    std::vector<Share> out;
    for (std::size_t i : indices) out.push_back(shares[i]);
    return out;
}

}  // namespace shamir::test

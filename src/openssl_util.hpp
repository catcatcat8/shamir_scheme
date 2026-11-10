// Internal RAII wrappers and helpers around OpenSSL BIGNUM / EC types.
#pragma once

#include <memory>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "shamir.hpp"

namespace shamir::internal {

struct BnDeleter {
    // BN_clear_free wipes the value before freeing, because many BIGNUMs
    // here hold secrets or polynomial coefficients.
    void operator()(BIGNUM* bn) const { BN_clear_free(bn); }
};
struct CtxDeleter {
    void operator()(BN_CTX* ctx) const { BN_CTX_free(ctx); }
};
struct PointDeleter {
    void operator()(EC_POINT* point) const { EC_POINT_clear_free(point); }
};

using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using CtxPtr = std::unique_ptr<BN_CTX, CtxDeleter>;
using PointPtr = std::unique_ptr<EC_POINT, PointDeleter>;

/// Throws `Error` with the given message if `ok` is not 1.
void check(int ok, const char* what);

BnPtr new_bn();
CtxPtr new_ctx();
PointPtr new_point();

BnPtr bn_from_scalar(const Scalar& scalar);
BnPtr bn_from_uint(unsigned long value);
Scalar scalar_from_bn(const BIGNUM* bn);

/// The secp256k1 group. Lives for the whole program.
const EC_GROUP* curve();

/// The order n of the secp256k1 group (a 256-bit prime).
const BIGNUM* order();

/// Returns true if 0 <= value < n.
bool less_than_order(const Scalar& value);

}  // namespace shamir::internal

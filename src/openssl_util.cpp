#include "openssl_util.hpp"

#include <openssl/err.h>
#include <openssl/obj_mac.h>

#include <string>

namespace shamir::internal {

void check(int ok, const char* what) {
    if (ok != 1) {
        const unsigned long code = ERR_get_error();
        std::string message = std::string("OpenSSL error in ") + what;
        if (code != 0) {
            char buffer[256];
            ERR_error_string_n(code, buffer, sizeof buffer);
            message += ": ";
            message += buffer;
        }
        ERR_clear_error();
        throw Error(message);
    }
}

BnPtr new_bn() {
    BnPtr bn(BN_new());
    if (!bn) throw Error("BN_new failed");
    return bn;
}

CtxPtr new_ctx() {
    CtxPtr ctx(BN_CTX_secure_new());
    if (!ctx) throw Error("BN_CTX_secure_new failed");
    return ctx;
}

PointPtr new_point() {
    PointPtr point(EC_POINT_new(curve()));
    if (!point) throw Error("EC_POINT_new failed");
    return point;
}

BnPtr bn_from_scalar(const Scalar& scalar) {
    BnPtr bn(BN_bin2bn(scalar.bytes().data(), static_cast<int>(kScalarSize), nullptr));
    if (!bn) throw Error("BN_bin2bn failed");
    // Ask OpenSSL to use constant-time code paths where it has them.
    BN_set_flags(bn.get(), BN_FLG_CONSTTIME);
    return bn;
}

BnPtr bn_from_uint(unsigned long value) {
    BnPtr bn = new_bn();
    check(BN_set_word(bn.get(), value), "BN_set_word");
    return bn;
}

Scalar scalar_from_bn(const BIGNUM* bn) {
    std::array<std::uint8_t, kScalarSize> bytes{};
    if (BN_bn2binpad(bn, bytes.data(), static_cast<int>(bytes.size())) != static_cast<int>(kScalarSize)) {
        throw Error("BN_bn2binpad failed: value does not fit in 32 bytes");
    }
    Scalar result(bytes);
    OPENSSL_cleanse(bytes.data(), bytes.size());
    return result;
}

namespace {

struct GroupHolder {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    ~GroupHolder() { EC_GROUP_free(group); }
};

}  // namespace

const EC_GROUP* curve() {
    static const GroupHolder holder;
    if (holder.group == nullptr) throw Error("secp256k1 is not available in this OpenSSL build");
    return holder.group;
}

const BIGNUM* order() {
    const BIGNUM* n = EC_GROUP_get0_order(curve());
    if (n == nullptr) throw Error("EC_GROUP_get0_order failed");
    return n;
}

bool less_than_order(const Scalar& value) {
    BnPtr bn = bn_from_scalar(value);
    return BN_cmp(bn.get(), order()) < 0;
}

}  // namespace shamir::internal

#include <iostream>
#include <string>
#include <iomanip>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <cmath>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ossl_typ.h>
#include <cstdlib>

/* Возвращает SHA-256 hash */
std::string sha256(const std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

/* Генерация приватного ключа ECDSA сurve25519 */
std::string curve25519_pr_key_gen() {
    unsigned char buf[32];
    RAND_bytes(buf, 32);  //генерируем 32 рандомных байта
    std::string s_buf;
    s_buf += std::string(buf, buf+32);  //переводим unsigned char buf в std::string
    std::string curve25519_pr_key = sha256(s_buf);
    return curve25519_pr_key;
}

BIGNUM *polinom(std::vector<uint64_t> coefs, std::string secr, int x) {
    int cur_pow = 1;
    BIGNUM *result = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    uint64_t cur_result = 0;
    for (auto i: coefs) {
        cur_result += (pow(x,cur_pow)*i);
        cur_pow += 1;
    }
    std::string _s = std::to_string(cur_result);
    char const *str= _s.c_str();
    BIGNUM *pre_res = NULL;

    BN_dec2bn(&pre_res, str);
    BIGNUM *p = NULL;  //переводим secret в BIGNUM
    const char *pr_key = secr.c_str();
    BN_hex2bn(&p, pr_key);
    BN_add(result, p, pre_res);
    return result;
}

/* Разделение секрета на N частей */
std::vector<std::pair<int, std::string>> split(std::string secret, uint16_t n, uint16_t t) {
    std::vector<std::string> shares;
    std::vector<std::pair<int, std::string>> shares_bignum;  //куски - точки типа (int, BIGNUM)
    std::vector<BIGNUM*> coefs_bignum;

    std::vector<uint64_t> coefs;
    for (int i = 1; i<t; i++) {
        coefs.push_back((1 + std::rand() % (18446744073709551614)));
    }
    /*
    for (auto i: coefs) {  //переводим все коэффициенты в BIGNUM
        char *str;
        sprintf(str, "%d", i);  //int to char
        BIGNUM *our_number = BN_new();
        BN_dec2bn(&our_number, str);  //char(dec) to BIGNUM
        coefs_bignum.push_back(*our_number);
    }
    */
    for (int i=0; i<n; i++) {
        BIGNUM *share = BN_new();
        share = polinom(coefs, secret, i+1);
        char * number_str = BN_bn2hex(share);
        std::string str(number_str);
        shares_bignum.push_back({ i+1, str});
    }
    return shares_bignum;
}

int main() {
    srand ( time(NULL) );
    uint16_t N;
    uint16_t T;
    std::string curve25519_private_key = curve25519_pr_key_gen();
    std::cout << "stdin:\n" << curve25519_private_key << std::endl;
    std::cin >> N >> T;
    std::vector<std::pair<int, std::string>> shares = split(curve25519_private_key, N, T);
    std::cout << "\nstdout:\n";
    for (auto share : shares) {
        std::cout << "(" <<share.first << "; " << share.second << ")\n";
    }
    return 0;
}

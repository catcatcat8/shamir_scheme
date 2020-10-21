#include <iostream>
#include <cstring>
#include <string>
#include <iomanip>
#include <vector>
#include <cmath>
#include <locale>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ossl_typ.h>

/* Split строки по пробелам */
std::vector<std::string> split(std::string line) {
    std::vector<std::string> words;
    std::string buffer = "";      //буфферная строка
    for(int i=0; i <= line.size(); i++){
        if(line[i] != ' '){      // " " сплиттер
            buffer += line[i];
        }
        else{
            words.push_back(buffer);
            buffer = "";
        }
    }
    words.push_back(buffer);
    return words;
}

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

/* Возвращает результат полинома n-1 степени от x: f(x) = secret + a(1) * x + a(2) * x^2 + ... + a(n-1) * x^(n-1) */
BIGNUM *polinom(std::vector<std::string> coefs, std::string secr, int x) {
    BIGNUM *result = NULL;
    BN_dec2bn(&result, "0");
    int j = 1;  //текущая степень x

    BIGNUM *sum = NULL;  //результат полинома без сложения с секретом
    BN_dec2bn(&sum, "0");

    for (auto i: coefs) {
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *coef_pov_res = NULL;
        BIGNUM *coef_res = NULL;

        const char * c = i.c_str();
        BN_hex2bn(&coef_res, c);  //переводим коэффициент в BIGNUM(hex)

        BIGNUM *pow = NULL;  //результат возведения в степень x
        BN_dec2bn(&pow, "1");

        std::string x_str = std::to_string(x);
        char const *x_char = x_str.c_str();
        BIGNUM *our_x = NULL;
        BN_dec2bn(&our_x, x_char);
        for (int cur_pow=1; cur_pow<=j; cur_pow++) {  //возводим x в степень j
            BN_mul(pow, our_x, pow, ctx);
        }

        BN_mul(coef_res, pow, coef_res, ctx);  //результат x*a(j)
        BN_add(sum, sum, coef_res);  //накапливаем сумму a(j)*x^j

        j++;
        BN_free(coef_pov_res);
        BN_free(coef_res);
    }

    BIGNUM *p = NULL;  //переводим secret в BIGNUM
    const char *pr_key = secr.c_str();
    BN_hex2bn(&p, pr_key);
    BN_add(result, p, sum);  //результат полинома

    return result;
}

/* Разделение секрета на N частей */
std::vector<std::pair<int, std::string>> split(std::string secret, uint16_t n, uint16_t t) {
    std::vector<std::pair<int, std::string>> shares_bignum;  //куски - точки типа (int; BIGNUM)

    std::vector<std::string> coefs;  //массив рандомных коэффициентов полинома

    for (int i=1; i<t; i++) {  //генерация t-1 коэффициентов
        unsigned char buf[16];
        RAND_bytes(buf, 16);  //генерируем 32 рандомных байта коэффициента
        std::string str_buf((char*)buf);
        std::string cur_cof = sha256(str_buf);  //коэффициент - sha256(random 32 bytes)
        coefs.push_back(cur_cof);
    }

    for (int i=0; i<n; i++) {  //запись n кусков в массив пар shares_bignum
        BIGNUM *share = BN_new();
        share = polinom(coefs, secret, i+1);

        char * number_str = BN_bn2hex(share);
        std::string str(number_str);
        shares_bignum.push_back({ i+1, str});  //записываем точку (i+1; share[i+1])

        BN_free(share);
        OPENSSL_free(number_str);
    }

    return shares_bignum;
}

/* Восстановление секрета по T частям */
std::string recover(std::vector<std::pair<int, std::string>> shares) {
    std::vector<double> x;  //коэффициенты x частей секрета
    std::vector<std::string> y;  //коэффициенты y частей секрета

    for (auto i: shares) {
        x.push_back(i.first*1.0);
    }
    for (auto i: shares) {
        y.push_back(i.second);
    }

    /* Возвращение исходной полиномиальной функции */
    std::vector<std::string> mul;

    std::vector<double> x_divs;
    for (int j=0; j<x.size(); j++) {
        double result = 1.0;
        for (int i = 0; i < x.size(); i++) {
            int m = i;
            if (m != j) {
                double slag = (0 - x[m]) / (x[j] - x[m]);
                result *= slag;
            }
        }
        x_divs.push_back(result);
    }

    int ind_cur_y = 0;
    for (auto i : x_divs) {
        BIGNUM *mul_result = NULL;
        BN_dec2bn(&mul_result, "0");
        BN_CTX *ctx = BN_CTX_new();

        BIGNUM *cur_y = NULL;
        const char * cur_y_char = y[ind_cur_y].c_str();
        BN_hex2bn(&cur_y, cur_y_char);

        BIGNUM *cur_x = NULL;
        std::string x_double = std::to_string(i);
        const char * x_char = x_double.c_str();
        BN_dec2bn(&cur_x, x_char);

        BN_mul(mul_result, cur_x, cur_y, ctx);
        char *result_str = BN_bn2dec(mul_result);
        std::string str(result_str);
        mul.push_back(str);
        OPENSSL_free(result_str);
        ind_cur_y++;
    }

    BIGNUM *final_res = NULL;
    BN_dec2bn(&final_res, "0");
    for (auto i : mul) {
        const char * c = i.c_str();
        BIGNUM *sl = NULL;
        BN_dec2bn(&sl, c);
        BN_add(final_res, final_res, sl);
    }

    char *fn_res = BN_bn2hex(final_res);
    std::string fn_result(fn_res);
    OPENSSL_free(fn_res);

    return fn_result;
}

int main(int argc, char* argv[]) {

    if ((std::string(argv[1]) != "split") && (std::string(argv[1]) != "recover")) {
        std::cout << "Проверьте правильность введенных вами данных!\n";
        return 1;
    }

    if (std::string(argv[1]) == "split") {  //mode: split
        uint16_t N;
        uint16_t T;
        std::string curve25519_private_key = curve25519_pr_key_gen();  //генерация приватного ключа
        std::cout << "stdin:\n" << curve25519_private_key << std::endl;
        std::cin >> N >> T;

        std::vector<std::pair<int, std::string>> shares = split(curve25519_private_key, N,
                                                                T);  //разделение приватного ключа на N кусков

        std::cout << "\nstdout:\n";
        for (auto share : shares) {
            std::cout << share.first << " " << share.second << "\n";
        }
    }

    if (std::string(argv[1]) == "recover") {  //mode: recover
        std::vector<std::pair<int, std::string>> recover_parts;

        std::string input_share;
        std::cout << "stdin:\n";
        getline(std::cin, input_share);
        while (input_share != "") {  //ввод частей в режиме recover с клавиатуры
            std::vector<std::string> split_result = split(input_share);
            int x_point = stoi(split_result[0]);
            recover_parts.push_back({x_point, split_result[1]});
            getline(std::cin, input_share);
        }

        std::string private_key_recover = recover(recover_parts);
        std::cout << "\nstdout:\n";
        std::locale loc;
        for (std::string::size_type i=0; i<private_key_recover.length(); ++i)
            std::cout << std::tolower(private_key_recover[i],loc);
        std::cout << "\n";
    }

    return 0;
}

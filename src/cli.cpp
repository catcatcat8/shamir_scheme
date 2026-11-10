// Command-line interface for splitting and combining secp256k1 private keys.
//
// Secrets are never accepted as command-line arguments (they would end up in
// shell history and in the process list); they are read from stdin instead.

#include <openssl/crypto.h>

#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "shamir.hpp"
#include "shamir_keys.hpp"

namespace {

constexpr int kExitError = 1;
constexpr int kExitUsage = 2;

constexpr std::string_view kCommitmentsPrefix = "commitments:";

const char* const kUsage = R"(Usage:
  shamir split -t <threshold> -n <shares> [--generate] [--verifiable]
      Split a secp256k1 private key into <shares> shares; any <threshold>
      of them recover the key. The key is read as hex from stdin, or a new
      one is generated with --generate. Prints one share per line ("x:y").
      With --verifiable, also prints Feldman commitments ("commitments:...").

  shamir combine [--commitments <list>] [<share>...]
      Recover the private key from shares. Shares (and an optional
      "commitments:..." line) are read from stdin when not given as
      arguments. With commitments, every share is verified first.

  shamir verify --commitments <list> [<share>...]
      Check shares against Feldman commitments without combining them.

  shamir address
      Read a hex private key from stdin; print its public key and
      Ethereum address.
)";

struct UsageError {
    std::string message;
};

void wipe(std::string& s) {
    if (!s.empty()) OPENSSL_cleanse(s.data(), s.size());
    s.clear();
}

std::string trim(std::string_view s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(first, last - first + 1));
}

unsigned parse_count(std::string_view name, const std::string& value) {
    if (value.empty() || value.size() > 3 || value.find_first_not_of("0123456789") != std::string::npos) {
        throw UsageError{std::string(name) + " must be a number from 1 to 255"};
    }
    return static_cast<unsigned>(std::stoul(value));
}

shamir::Scalar read_key_from_stdin() {
    std::string line;
    std::getline(std::cin, line);
    std::string text = trim(line);
    wipe(line);
    try {
        shamir::Scalar key = shamir::Scalar::from_hex(text);
        wipe(text);
        shamir::require_valid_private_key(key);
        return key;
    } catch (...) {
        wipe(text);
        throw;
    }
}

void print_key_info(const shamir::Scalar& key, std::ostream& out) {
    const auto pub = shamir::public_key(key);
    out << "public key: " << shamir::to_hex(pub.data(), pub.size()) << "\n";
    out << "address:    " << shamir::ethereum_address(key) << "\n";
}

int cmd_split(const std::vector<std::string>& args) {
    std::optional<unsigned> threshold;
    std::optional<unsigned> count;
    bool generate = false;
    bool verifiable = false;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];
        auto value = [&]() -> const std::string& {
            if (i + 1 >= args.size()) throw UsageError{arg + " needs a value"};
            return args[++i];
        };
        if (arg == "-t" || arg == "--threshold") {
            threshold = parse_count("threshold", value());
        } else if (arg == "-n" || arg == "--shares") {
            count = parse_count("share count", value());
        } else if (arg == "--generate") {
            generate = true;
        } else if (arg == "--verifiable") {
            verifiable = true;
        } else {
            throw UsageError{"unknown option for split: " + arg};
        }
    }
    if (!threshold || !count) throw UsageError{"split needs -t <threshold> and -n <shares>"};

    const shamir::Scalar key = generate ? shamir::generate_private_key() : read_key_from_stdin();

    // Key details go to stderr, so stdout holds only shares and commitments.
    std::cerr << (generate ? "Generated a new secp256k1 private key.\n" : "");
    print_key_info(key, std::cerr);

    if (verifiable) {
        const auto result = shamir::split_verifiable(key, *threshold, *count);
        for (const auto& share : result.shares) std::cout << share.to_string() << "\n";
        std::cout << kCommitmentsPrefix << result.commitments.to_string() << "\n";
    } else {
        for (const auto& share : shamir::split(key, *threshold, *count)) std::cout << share.to_string() << "\n";
    }
    return 0;
}

struct ShareInput {
    std::vector<shamir::Share> shares;
    std::optional<shamir::Commitments> commitments;
};

ShareInput parse_share_input(const std::vector<std::string>& args) {
    ShareInput input;
    std::vector<std::string> share_texts;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--commitments") {
            if (i + 1 >= args.size()) throw UsageError{"--commitments needs a value"};
            input.commitments = shamir::Commitments::from_string(args[++i]);
        } else if (!args[i].empty() && args[i][0] == '-') {
            throw UsageError{"unknown option: " + args[i]};
        } else {
            share_texts.push_back(args[i]);
        }
    }
    if (share_texts.empty()) {
        std::string line;
        while (std::getline(std::cin, line)) {
            std::string text = trim(line);
            wipe(line);
            if (text.empty()) continue;
            if (std::string_view(text).substr(0, kCommitmentsPrefix.size()) == kCommitmentsPrefix) {
                if (!input.commitments) {
                    input.commitments = shamir::Commitments::from_string(text.substr(kCommitmentsPrefix.size()));
                }
            } else {
                share_texts.push_back(text);
            }
            wipe(text);
        }
    }
    for (auto& text : share_texts) {
        input.shares.push_back(shamir::Share::from_string(text));
        wipe(text);
    }
    if (input.shares.empty()) throw UsageError{"no shares given"};
    return input;
}

int cmd_combine(const std::vector<std::string>& args) {
    const ShareInput input = parse_share_input(args);
    const shamir::Scalar key = input.commitments ? shamir::combine_verified(input.shares, *input.commitments)
                                                 : shamir::combine(input.shares);
    if (!shamir::is_valid_private_key(key)) {
        throw shamir::Error("the shares do not combine to a valid private key");
    }
    if (input.commitments) std::cerr << "All shares match the commitments.\n";
    std::cout << key.to_hex() << "\n";
    return 0;
}

int cmd_verify(const std::vector<std::string>& args) {
    const ShareInput input = parse_share_input(args);
    if (!input.commitments) throw UsageError{"verify needs --commitments or a commitments: line on stdin"};
    bool all_valid = true;
    for (const auto& share : input.shares) {
        const bool valid = shamir::verify_share(share, *input.commitments);
        all_valid = all_valid && valid;
        std::cout << static_cast<unsigned>(share.x) << ": " << (valid ? "valid" : "INVALID") << "\n";
    }
    return all_valid ? 0 : kExitError;
}

int cmd_address(const std::vector<std::string>& args) {
    if (!args.empty()) throw UsageError{"address takes no arguments; the key is read from stdin"};
    print_key_info(read_key_from_stdin(), std::cout);
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << kUsage;
        return kExitUsage;
    }
    const std::string command = argv[1];
    const std::vector<std::string> args(argv + 2, argv + argc);
    try {
        if (command == "split") return cmd_split(args);
        if (command == "combine") return cmd_combine(args);
        if (command == "verify") return cmd_verify(args);
        if (command == "address") return cmd_address(args);
        if (command == "-h" || command == "--help" || command == "help") {
            std::cout << kUsage;
            return 0;
        }
        throw UsageError{"unknown command: " + command};
    } catch (const UsageError& e) {
        std::cerr << "error: " << e.message << "\n\n" << kUsage;
        return kExitUsage;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return kExitError;
    }
}

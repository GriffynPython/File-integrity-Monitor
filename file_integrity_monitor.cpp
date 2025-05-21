#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <unordered_map>

namespace fs = std::filesystem;

// Generate SHA256 hash of a file using OpenSSL EVP
std::string sha256_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file)
        return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    EVP_DigestInit_ex(ctx, md, nullptr);

    char buffer[8192];
    while (file.good()) {
        file.read(buffer, sizeof(buffer));
        EVP_DigestUpdate(ctx, buffer, file.gcount());
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream result;
    for (unsigned int i = 0; i < hash_len; ++i)
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return result.str();
}

// Save current hashes as baseline
void create_baseline(const std::string& path, const std::string& baseline_file) {
    std::ofstream out(baseline_file);
    for (const auto& entry : fs::recursive_directory_iterator(path)) {
        if (fs::is_regular_file(entry.path())) {
            std::string abs_path = fs::absolute(entry.path()).string();
            std::string hash = sha256_file(abs_path);
            out << abs_path << " " << hash << "\n";
        }
    }
    std::cout << "[+] Baseline created at " << baseline_file << "\n";
}

// Compare current state to baseline
void verify_integrity(const std::string& path, const std::string& baseline_file) {
    std::unordered_map<std::string, std::string> baseline;

    // Read baseline file into map
    std::ifstream in(baseline_file);
    std::string line, filepath, hash;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        iss >> filepath >> hash;
        baseline[filepath] = hash;
    }

    std::unordered_map<std::string, bool> seen;

    std::cout << "[*] Verifying integrity...\n";
    for (const auto& entry : fs::recursive_directory_iterator(path)) {
        if (fs::is_regular_file(entry.path())) {
            std::string abs_path = fs::absolute(entry.path()).string();
            std::string current_hash = sha256_file(abs_path);
            seen[abs_path] = true;

            auto it = baseline.find(abs_path);
            if (it == baseline.end()) {
                std::cout << "[NEW] " << abs_path << "\n";
            } else if (it->second != current_hash) {
                std::cout << "[MODIFIED] " << abs_path << "\n";
            }
        }
    }

    // Check for deleted files
    for (const auto& [file, _] : baseline) {
        if (!seen[file] && !fs::exists(file)) {
            std::cout << "[DELETED] " << file << "\n";
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cout << "Usage:\n"
                  << "  " << argv[0] << " -create <directory> <baseline_file>\n"
                  << "  " << argv[0] << " -verify <directory> <baseline_file>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string path = argv[2];
    std::string baseline_file = argv[3];

    if (mode == "-create") {
        create_baseline(path, baseline_file);
    } else if (mode == "-verify") {
        verify_integrity(path, baseline_file);
    } else {
        std::cerr << "Unknown mode.\n";
    }

    return 0;
}


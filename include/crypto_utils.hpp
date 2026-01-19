// Copyright 2026 Pete Matern
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#pragma once

#include <expected>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <spdlog/spdlog.h>

namespace wamp {

// ============================================================================
// RAII Deleters for OpenSSL Types
// ============================================================================

struct PKEYDeleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};

struct MDCTXDeleter {
    void operator()(EVP_MD_CTX* ctx) const { if (ctx) EVP_MD_CTX_free(ctx); }
};

// ============================================================================
// Hex Encoding/Decoding Utilities
// ============================================================================

inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::string result;
    result.reserve(bytes.size() * 2);

    for (uint8_t byte : bytes) {
        constexpr char hex_chars[] = "0123456789abcdef";
        result.push_back(hex_chars[byte >> 4]);
        result.push_back(hex_chars[byte & 0x0F]);
    }

    return result;
}

inline std::expected<std::vector<uint8_t>, std::string> hex_to_bytes(const std::string& hex) {
    // Must be even length
    if (hex.length() % 2 != 0) {
        return std::unexpected{"Hex string must have even length"};
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        char high = hex[i];
        char low = hex[i + 1];

        auto hex_char_to_int = [](char c) -> std::expected<uint8_t, std::string> {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return std::unexpected{"Invalid hex character"};
        };

        auto high_val = hex_char_to_int(high);
        if (!high_val) return std::unexpected{high_val.error()};

        auto low_val = hex_char_to_int(low);
        if (!low_val) return std::unexpected{low_val.error()};

        bytes.push_back((*high_val << 4) | *low_val);
    }

    return bytes;
}

// ============================================================================
// Cryptographic Challenge Generation
// ============================================================================

inline std::string generate_challenge() {
    // Generate 32 bytes of cryptographically secure random data
    std::vector<uint8_t> challenge_bytes(32);

    if (RAND_bytes(challenge_bytes.data(), static_cast<int>(challenge_bytes.size())) != 1) {
        spdlog::error("Failed to generate random challenge: {}",
            ERR_error_string(ERR_get_error(), nullptr));
        // Return empty string on error (caller should check and disconnect client)
        return "";
    }

    return bytes_to_hex(challenge_bytes);
}

// ============================================================================
// Ed25519 Signature Verification
// ============================================================================

inline bool verify_ed25519_signature(
    const std::string& signature_hex,
    const std::string& message,
    const std::string& public_key_hex
) {
    // Decode hex-encoded signature (64 bytes = 128 hex chars)
    auto signature_bytes = hex_to_bytes(signature_hex);
    if (!signature_bytes) {
        spdlog::debug("Invalid signature hex encoding: {}", signature_bytes.error());
        return false;
    }

    if (signature_bytes->size() != 64) {
        spdlog::debug("Invalid signature length: {} (expected 64)", signature_bytes->size());
        return false;
    }

    // Decode hex-encoded public key (32 bytes = 64 hex chars)
    auto public_key_bytes = hex_to_bytes(public_key_hex);
    if (!public_key_bytes) {
        spdlog::debug("Invalid public key hex encoding: {}", public_key_bytes.error());
        return false;
    }

    if (public_key_bytes->size() != 32) {
        spdlog::debug("Invalid public key length: {} (expected 32)", public_key_bytes->size());
        return false;
    }

    // Create EVP_PKEY from raw Ed25519 public key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        public_key_bytes->data(),
        public_key_bytes->size()
    );

    if (!pkey) {
        spdlog::error("Failed to create EVP_PKEY from public key: {}",
            ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }

    std::unique_ptr<EVP_PKEY, PKEYDeleter> pkey_guard(pkey);

    // Create message digest context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        spdlog::error("Failed to create EVP_MD_CTX: {}",
            ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }

    std::unique_ptr<EVP_MD_CTX, MDCTXDeleter> md_ctx_guard(md_ctx);

    // Initialize verification context
    if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey) != 1) {
        spdlog::error("EVP_DigestVerifyInit failed: {}",
            ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }

    // Verify signature
    int verify_result = EVP_DigestVerify(
        md_ctx,
        signature_bytes->data(),
        signature_bytes->size(),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size()
    );

    if (verify_result == 1) {
        return true;
    } else if (verify_result == 0) {
        spdlog::debug("Signature verification failed: invalid signature");
        return false;
    } else {
        spdlog::error("EVP_DigestVerify error: {}",
            ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }
}

// ============================================================================
// Ed25519 Private Key Loading
// ============================================================================

inline std::expected<std::unique_ptr<EVP_PKEY, PKEYDeleter>, std::string>
load_ed25519_private_key_pem(const std::string& pem_path) {
    // Open and read PEM file
    std::ifstream file(pem_path);
    if (!file.is_open()) {
        return std::unexpected{"Failed to open private key file: " + pem_path};
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string pem_content = buffer.str();
    file.close();

    // Create BIO from PEM content
    BIO* bio = BIO_new_mem_buf(pem_content.data(), static_cast<int>(pem_content.size()));
    if (!bio) {
        return std::unexpected{"Failed to create BIO for PEM parsing"};
    }

    // RAII wrapper for BIO
    struct BIODeleter {
        void operator()(BIO* b) const { if (b) BIO_free(b); }
    };
    std::unique_ptr<BIO, BIODeleter> bio_guard(bio);

    // Read private key from PEM
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        return std::unexpected{"Failed to parse PEM private key: " +
            std::string(ERR_error_string(ERR_get_error(), nullptr))};
    }

    // Verify it's an Ed25519 key
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(pkey);
        return std::unexpected{"Key is not Ed25519 type"};
    }

    return std::unique_ptr<EVP_PKEY, PKEYDeleter>(pkey);
}

// ============================================================================
// Ed25519 Signing
// ============================================================================

inline std::expected<std::string, std::string> sign_ed25519(
    const std::string& message,
    EVP_PKEY* private_key
) {
    if (!private_key) {
        return std::unexpected{"Private key is null"};
    }

    // Verify it's an Ed25519 key
    if (EVP_PKEY_id(private_key) != EVP_PKEY_ED25519) {
        return std::unexpected{"Key is not Ed25519 type"};
    }

    // Create message digest context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return std::unexpected{"Failed to create EVP_MD_CTX: " +
            std::string(ERR_error_string(ERR_get_error(), nullptr))};
    }

    std::unique_ptr<EVP_MD_CTX, MDCTXDeleter> md_ctx_guard(md_ctx);

    // Initialize signing context (Ed25519 doesn't use a digest, pass nullptr)
    if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, private_key) != 1) {
        return std::unexpected{"EVP_DigestSignInit failed: " +
            std::string(ERR_error_string(ERR_get_error(), nullptr))};
    }

    // Get signature length
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx,
                       nullptr, &sig_len,
                       reinterpret_cast<const unsigned char*>(message.data()),
                       message.size()) != 1) {
        return std::unexpected{"EVP_DigestSign (get length) failed: " +
            std::string(ERR_error_string(ERR_get_error(), nullptr))};
    }

    // Ed25519 signatures are always 64 bytes
    if (sig_len != 64) {
        return std::unexpected{"Unexpected Ed25519 signature length: " + std::to_string(sig_len)};
    }

    // Sign the message
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(md_ctx,
                       signature.data(), &sig_len,
                       reinterpret_cast<const unsigned char*>(message.data()),
                       message.size()) != 1) {
        return std::unexpected{"EVP_DigestSign failed: " +
            std::string(ERR_error_string(ERR_get_error(), nullptr))};
    }

    // Return hex-encoded signature
    return bytes_to_hex(signature);
}

// ============================================================================
// Extract Raw Public Key from EVP_PKEY (for getting hex representation)
// ============================================================================

inline std::expected<std::string, std::string> get_ed25519_public_key_hex(EVP_PKEY* pkey) {
    if (!pkey) {
        return std::unexpected{"Key is null"};
    }

    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        return std::unexpected{"Key is not Ed25519 type"};
    }

    size_t pub_len = 32;
    std::vector<uint8_t> pub_key(pub_len);

    if (EVP_PKEY_get_raw_public_key(pkey, pub_key.data(), &pub_len) != 1) {
        return std::unexpected{"Failed to get raw public key: " +
            std::string(ERR_error_string(ERR_get_error(), nullptr))};
    }

    return bytes_to_hex(pub_key);
}

} // namespace wamp

// Copyright 2026 Patrick Matern
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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <spdlog/spdlog.h>

namespace wamp {

// ============================================================================
// Hex Encoding/Decoding Utilities
// ============================================================================

inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);

    for (uint8_t byte : bytes) {
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

    // RAII wrapper for EVP_PKEY
    struct PKEYDeleter {
        void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
    };
    std::unique_ptr<EVP_PKEY, PKEYDeleter> pkey_guard(pkey);

    // Create message digest context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        spdlog::error("Failed to create EVP_MD_CTX: {}",
            ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }

    // RAII wrapper for EVP_MD_CTX
    struct MDCTXDeleter {
        void operator()(EVP_MD_CTX* ctx) const { if (ctx) EVP_MD_CTX_free(ctx); }
    };
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

} // namespace wamp

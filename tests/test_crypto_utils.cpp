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


#include <catch2/catch_test_macros.hpp>
#include "include/crypto_utils.hpp"
#include <fstream>
#include <atomic>

using namespace wamp;

TEST_CASE("Hex encoding/decoding utilities", "[crypto]") {
    SECTION("bytes_to_hex converts bytes to lowercase hex") {
        std::vector<uint8_t> bytes{0x00, 0x01, 0x0a, 0x0f, 0x10, 0xff};
        auto hex = bytes_to_hex(bytes);
        REQUIRE(hex == "00010a0f10ff");
    }

    SECTION("bytes_to_hex handles empty vector") {
        std::vector<uint8_t> empty{};
        auto hex = bytes_to_hex(empty);
        REQUIRE(hex.empty());
    }

    SECTION("hex_to_bytes converts hex to bytes") {
        auto result = hex_to_bytes("00010a0f10ff");
        REQUIRE(result.has_value());
        REQUIRE(result->size() == 6);
        REQUIRE((*result)[0] == 0x00);
        REQUIRE((*result)[1] == 0x01);
        REQUIRE((*result)[2] == 0x0a);
        REQUIRE((*result)[3] == 0x0f);
        REQUIRE((*result)[4] == 0x10);
        REQUIRE((*result)[5] == 0xff);
    }

    SECTION("hex_to_bytes handles uppercase hex") {
        auto result = hex_to_bytes("AABBCCDD");
        REQUIRE(result.has_value());
        REQUIRE(result->size() == 4);
        REQUIRE((*result)[0] == 0xaa);
        REQUIRE((*result)[1] == 0xbb);
        REQUIRE((*result)[2] == 0xcc);
        REQUIRE((*result)[3] == 0xdd);
    }

    SECTION("hex_to_bytes handles mixed case") {
        auto result = hex_to_bytes("AaBbCcDd");
        REQUIRE(result.has_value());
        REQUIRE(result->size() == 4);
    }

    SECTION("hex_to_bytes fails on odd length") {
        auto result = hex_to_bytes("abc");
        REQUIRE(!result.has_value());
        REQUIRE(result.error() == "Hex string must have even length");
    }

    SECTION("hex_to_bytes fails on invalid characters") {
        auto result = hex_to_bytes("ghij");
        REQUIRE(!result.has_value());
        REQUIRE(result.error() == "Invalid hex character");
    }

    SECTION("Round-trip conversion") {
        std::vector<uint8_t> original{0xde, 0xad, 0xbe, 0xef};
        auto hex = bytes_to_hex(original);
        auto result = hex_to_bytes(hex);
        REQUIRE(result.has_value());
        REQUIRE(*result == original);
    }
}

TEST_CASE("Challenge generation", "[crypto]") {
    SECTION("generate_challenge returns 64 hex characters (32 bytes)") {
        auto challenge = generate_challenge();
        REQUIRE(!challenge.empty());
        REQUIRE(challenge.length() == 64);

        // Verify it's valid hex
        auto bytes = hex_to_bytes(challenge);
        REQUIRE(bytes.has_value());
        REQUIRE(bytes->size() == 32);
    }

    SECTION("generate_challenge returns different values each call") {
        auto c1 = generate_challenge();
        auto c2 = generate_challenge();
        auto c3 = generate_challenge();

        REQUIRE(!c1.empty());
        REQUIRE(!c2.empty());
        REQUIRE(!c3.empty());

        // All should be unique (extremely unlikely to collide)
        REQUIRE(c1 != c2);
        REQUIRE(c2 != c3);
        REQUIRE(c1 != c3);
    }
}

// Counter to generate unique file names
static std::atomic<int> keypair_counter{0};

// Helper to create a test key pair in memory
static std::pair<std::string, std::string> create_test_keypair_files() {
    // Generate Ed25519 key pair using OpenSSL
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);

    if (!ctx) {
        throw std::runtime_error("Failed to create key context");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to init keygen");
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate key");
    }

    EVP_PKEY_CTX_free(ctx);

    // Extract raw public key and convert to hex
    size_t pub_len = 32;
    std::vector<uint8_t> pub_key(pub_len);
    EVP_PKEY_get_raw_public_key(pkey, pub_key.data(), &pub_len);
    std::string public_key_hex = bytes_to_hex(pub_key);

    // Write private key to temp file with unique name
    int id = keypair_counter++;
    std::string priv_path = "/tmp/test_ed25519_private_" + std::to_string(id) + ".pem";
    FILE* priv_file = fopen(priv_path.c_str(), "w");
    if (!priv_file) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to open private key file");
    }

    if (!PEM_write_PrivateKey(priv_file, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        fclose(priv_file);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write private key");
    }
    fclose(priv_file);

    EVP_PKEY_free(pkey);

    return {priv_path, public_key_hex};
}

TEST_CASE("Ed25519 PEM key loading", "[crypto]") {
    SECTION("load_ed25519_private_key_pem loads valid key") {
        auto [priv_path, public_key_hex] = create_test_keypair_files();

        auto result = load_ed25519_private_key_pem(priv_path);
        REQUIRE(result.has_value());
        REQUIRE(result->get() != nullptr);

        // Verify the key type
        REQUIRE(EVP_PKEY_id(result->get()) == EVP_PKEY_ED25519);

        // Clean up
        std::remove(priv_path.c_str());
    }

    SECTION("load_ed25519_private_key_pem fails on non-existent file") {
        auto result = load_ed25519_private_key_pem("/non/existent/path.pem");
        REQUIRE(!result.has_value());
        REQUIRE(result.error().find("Failed to open") != std::string::npos);
    }

    SECTION("load_ed25519_private_key_pem fails on invalid PEM") {
        // Create a file with invalid content
        std::string path = "/tmp/invalid_key.pem";
        std::ofstream file(path);
        file << "not a valid PEM file";
        file.close();

        auto result = load_ed25519_private_key_pem(path);
        REQUIRE(!result.has_value());

        std::remove(path.c_str());
    }
}

TEST_CASE("Ed25519 signing and verification", "[crypto]") {
    SECTION("sign_ed25519 produces valid signature") {
        auto [priv_path, public_key_hex] = create_test_keypair_files();

        auto key_result = load_ed25519_private_key_pem(priv_path);
        REQUIRE(key_result.has_value());

        std::string message = "test message to sign";
        auto sig_result = sign_ed25519(message, key_result->get());

        REQUIRE(sig_result.has_value());
        REQUIRE(sig_result->length() == 128);  // 64 bytes = 128 hex chars

        // Verify the signature is valid hex
        auto sig_bytes = hex_to_bytes(*sig_result);
        REQUIRE(sig_bytes.has_value());
        REQUIRE(sig_bytes->size() == 64);

        std::remove(priv_path.c_str());
    }

    SECTION("sign and verify round-trip") {
        auto [priv_path, public_key_hex] = create_test_keypair_files();

        auto key_result = load_ed25519_private_key_pem(priv_path);
        REQUIRE(key_result.has_value());

        std::string message = "challenge|0|testuser|user";
        auto sig_result = sign_ed25519(message, key_result->get());
        REQUIRE(sig_result.has_value());

        // Verify the signature
        bool verified = verify_ed25519_signature(*sig_result, message, public_key_hex);
        REQUIRE(verified);

        std::remove(priv_path.c_str());
    }

    SECTION("verify_ed25519_signature rejects tampered signature") {
        auto [priv_path, public_key_hex] = create_test_keypair_files();

        auto key_result = load_ed25519_private_key_pem(priv_path);
        REQUIRE(key_result.has_value());

        std::string message = "original message";
        auto sig_result = sign_ed25519(message, key_result->get());
        REQUIRE(sig_result.has_value());

        // Tamper with the signature by changing a character
        std::string tampered_sig = *sig_result;
        tampered_sig[0] = (tampered_sig[0] == 'a') ? 'b' : 'a';

        bool verified = verify_ed25519_signature(tampered_sig, message, public_key_hex);
        REQUIRE(!verified);

        std::remove(priv_path.c_str());
    }

    SECTION("verify_ed25519_signature rejects wrong message") {
        auto [priv_path, public_key_hex] = create_test_keypair_files();

        auto key_result = load_ed25519_private_key_pem(priv_path);
        REQUIRE(key_result.has_value());

        std::string message = "original message";
        auto sig_result = sign_ed25519(message, key_result->get());
        REQUIRE(sig_result.has_value());

        // Try to verify with different message
        bool verified = verify_ed25519_signature(*sig_result, "different message", public_key_hex);
        REQUIRE(!verified);

        std::remove(priv_path.c_str());
    }

    SECTION("verify_ed25519_signature rejects wrong public key") {
        auto [priv_path1, public_key_hex1] = create_test_keypair_files();
        auto [priv_path2, public_key_hex2] = create_test_keypair_files();

        auto key_result = load_ed25519_private_key_pem(priv_path1);
        REQUIRE(key_result.has_value());

        std::string message = "test message";
        auto sig_result = sign_ed25519(message, key_result->get());
        REQUIRE(sig_result.has_value());

        // Try to verify with wrong public key
        bool verified = verify_ed25519_signature(*sig_result, message, public_key_hex2);
        REQUIRE(!verified);

        std::remove(priv_path1.c_str());
        std::remove(priv_path2.c_str());
    }

    SECTION("sign_ed25519 rejects null key") {
        auto result = sign_ed25519("message", nullptr);
        REQUIRE(!result.has_value());
        REQUIRE(result.error() == "Private key is null");
    }
}

TEST_CASE("get_ed25519_public_key_hex", "[crypto]") {
    SECTION("extracts public key from private key") {
        auto [priv_path, expected_pub_hex] = create_test_keypair_files();

        auto key_result = load_ed25519_private_key_pem(priv_path);
        REQUIRE(key_result.has_value());

        auto pub_hex_result = get_ed25519_public_key_hex(key_result->get());
        REQUIRE(pub_hex_result.has_value());
        REQUIRE(pub_hex_result->length() == 64);  // 32 bytes = 64 hex chars
        REQUIRE(*pub_hex_result == expected_pub_hex);

        std::remove(priv_path.c_str());
    }

    SECTION("rejects null key") {
        auto result = get_ed25519_public_key_hex(nullptr);
        REQUIRE(!result.has_value());
        REQUIRE(result.error() == "Key is null");
    }
}

#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <span>
#include <expected>
#include <system_error>

namespace wamp::rawsocket {

// RawSocket protocol constants
constexpr uint8_t MAGIC_BYTE = 0x7F;
constexpr size_t HANDSHAKE_SIZE = 4;
constexpr size_t FRAME_HEADER_SIZE = 4;
constexpr uint32_t MAX_PAYLOAD_LENGTH = (1u << 24) - 1; // 24-bit max

// Serializer types (from spec)
enum class Serializer : uint8_t {
    ILLEGAL = 0,
    JSON = 1,
    MSGPACK = 2,
    CBOR = 3,
    // 4-15 reserved for future use
};

// Maximum message length codes (0-15 maps to 2^9 through 2^24)
enum class MaxLengthCode : uint8_t {
    BYTES_512 = 0,      // 2^9
    BYTES_1K = 1,       // 2^10
    BYTES_2K = 2,       // 2^11
    BYTES_4K = 3,       // 2^12
    BYTES_8K = 4,       // 2^13
    BYTES_16K = 5,      // 2^14
    BYTES_32K = 6,      // 2^15
    BYTES_64K = 7,      // 2^16
    BYTES_128K = 8,     // 2^17
    BYTES_256K = 9,     // 2^18
    BYTES_512K = 10,    // 2^19
    BYTES_1M = 11,      // 2^20
    BYTES_2M = 12,      // 2^21
    BYTES_4M = 13,      // 2^22
    BYTES_8M = 14,      // 2^23
    BYTES_16M = 15      // 2^24
};

// RawSocket handshake error codes (from spec)
enum class HandshakeError : uint8_t {
    SERIALIZER_UNSUPPORTED = 1,
    MAX_LENGTH_UNACCEPTABLE = 2,
    RESERVED_BITS_USED = 3,
    MAX_CONNECTIONS_REACHED = 4,
    // 5-15 reserved for future errors
};

// Message frame types (from spec)
enum class FrameType : uint8_t {
    REGULAR = 0,  // Regular WAMP message
    PING = 1,
    PONG = 2,
    // 3-7 reserved
};

// RawSocket-specific error codes
enum class RawSocketError {
    INVALID_MAGIC_BYTE = 100,
    INVALID_SERIALIZER = 101,
    INVALID_LENGTH_CODE = 102,
    RESERVED_BITS_SET = 103,
    INVALID_FRAME_TYPE = 104,
    PAYLOAD_TOO_LARGE = 105,
    INSUFFICIENT_DATA = 106,
    HANDSHAKE_FAILED = 107
};

class RawSocketErrorCategory : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override {
        return "rawsocket";
    }

    [[nodiscard]] std::string message(int ev) const override {
        switch (static_cast<RawSocketError>(ev)) {
            case RawSocketError::INVALID_MAGIC_BYTE:
                return "Invalid magic byte (expected 0x7F)";
            case RawSocketError::INVALID_SERIALIZER:
                return "Invalid or unsupported serializer";
            case RawSocketError::INVALID_LENGTH_CODE:
                return "Invalid maximum length code";
            case RawSocketError::RESERVED_BITS_SET:
                return "Reserved bits must be zero";
            case RawSocketError::INVALID_FRAME_TYPE:
                return "Invalid frame type";
            case RawSocketError::PAYLOAD_TOO_LARGE:
                return "Payload exceeds maximum message length";
            case RawSocketError::INSUFFICIENT_DATA:
                return "Insufficient data for complete message";
            case RawSocketError::HANDSHAKE_FAILED:
                return "RawSocket handshake failed";
            default:
                return "Unknown RawSocket error";
        }
    }
};

inline const RawSocketErrorCategory& rawsocket_error_category() {
    static RawSocketErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(RawSocketError e) {
    return {static_cast<int>(e), rawsocket_error_category()};
}

} // namespace wamp::rawsocket

// Register RawSocketError as error code enum
template<>
struct std::is_error_code_enum<wamp::rawsocket::RawSocketError> : std::true_type {};

namespace wamp::rawsocket {

struct HandshakeRequest {
    MaxLengthCode max_length;
    Serializer serializer;
};

struct HandshakeSuccess {
    MaxLengthCode max_length;
    Serializer serializer;
};

struct HandshakeErrorResponse {
    HandshakeError error;
};

struct FrameHeader {
    FrameType type;
    uint32_t payload_length;  // 24-bit value
};

// Convert MaxLengthCode to actual byte count
constexpr uint32_t max_length_to_bytes(MaxLengthCode code) {
    return 1u << (9 + static_cast<uint8_t>(code));
}

// Convert byte count to nearest MaxLengthCode (rounds up)
constexpr MaxLengthCode bytes_to_max_length(uint32_t bytes) {
    if (bytes <= 512) return MaxLengthCode::BYTES_512;
    if (bytes <= 1024) return MaxLengthCode::BYTES_1K;
    if (bytes <= 2048) return MaxLengthCode::BYTES_2K;
    if (bytes <= 4096) return MaxLengthCode::BYTES_4K;
    if (bytes <= 8192) return MaxLengthCode::BYTES_8K;
    if (bytes <= 16384) return MaxLengthCode::BYTES_16K;
    if (bytes <= 32768) return MaxLengthCode::BYTES_32K;
    if (bytes <= 65536) return MaxLengthCode::BYTES_64K;
    if (bytes <= 131072) return MaxLengthCode::BYTES_128K;
    if (bytes <= 262144) return MaxLengthCode::BYTES_256K;
    if (bytes <= 524288) return MaxLengthCode::BYTES_512K;
    if (bytes <= 1048576) return MaxLengthCode::BYTES_1M;
    if (bytes <= 2097152) return MaxLengthCode::BYTES_2M;
    if (bytes <= 4194304) return MaxLengthCode::BYTES_4M;
    if (bytes <= 8388608) return MaxLengthCode::BYTES_8M;
    return MaxLengthCode::BYTES_16M;
}

constexpr bool is_valid_serializer(uint8_t s) {
    return s >= 1 && s <= 3;  // JSON, MsgPack, CBOR
}

constexpr bool is_valid_max_length_code(uint8_t code) {
    return code <= 15;
}

// ============================================================================
// HANDSHAKE ENCODING/DECODING
// ============================================================================

// Encode client handshake request
// Format: [0x7F] [LLLL|SSSS] [0x00] [0x00]
inline std::array<uint8_t, HANDSHAKE_SIZE> encode_handshake_request(
    const HandshakeRequest& request
) {
    std::array<uint8_t, HANDSHAKE_SIZE> buffer{};

    buffer[0] = MAGIC_BYTE;
    buffer[1] = (static_cast<uint8_t>(request.max_length) << 4) |
                 static_cast<uint8_t>(request.serializer);
    buffer[2] = 0x00;
    buffer[3] = 0x00;

    return buffer;
}

// Encode router success response
inline std::array<uint8_t, HANDSHAKE_SIZE> encode_handshake_success(
    const HandshakeSuccess& response
) {
    std::array<uint8_t, HANDSHAKE_SIZE> buffer{};

    buffer[0] = MAGIC_BYTE;
    buffer[1] = (static_cast<uint8_t>(response.max_length) << 4) |
                 static_cast<uint8_t>(response.serializer);
    buffer[2] = 0x00;
    buffer[3] = 0x00;

    return buffer;
}

// Encode router error response
// Format: [0x7F] [EEEE|0000] [0x00] [0x00]
inline std::array<uint8_t, HANDSHAKE_SIZE> encode_handshake_error(
    HandshakeError error
) {
    std::array<uint8_t, HANDSHAKE_SIZE> buffer{};

    buffer[0] = MAGIC_BYTE;
    buffer[1] = static_cast<uint8_t>(error) << 4;  // Error in upper 4 bits
    buffer[2] = 0x00;
    buffer[3] = 0x00;

    return buffer;
}

// Decode handshake (can be request, success, or error)
inline std::expected<HandshakeRequest, std::error_code> decode_handshake_request(
    std::span<const uint8_t> data
) {
    if (data.size() < HANDSHAKE_SIZE) {
        return std::unexpected(make_error_code(RawSocketError::INSUFFICIENT_DATA));
    }

    // Validate magic byte
    if (data[0] != MAGIC_BYTE) {
        return std::unexpected(make_error_code(RawSocketError::INVALID_MAGIC_BYTE));
    }

    // Validate reserved octets
    if (data[2] != 0x00 || data[3] != 0x00) {
        return std::unexpected(make_error_code(RawSocketError::RESERVED_BITS_SET));
    }

    // Extract length and serializer
    uint8_t octet2 = data[1];
    uint8_t length_code = (octet2 >> 4) & 0x0F;
    uint8_t serializer = octet2 & 0x0F;

    // Validate values
    if (!is_valid_max_length_code(length_code)) {
        return std::unexpected(make_error_code(RawSocketError::INVALID_LENGTH_CODE));
    }

    if (!is_valid_serializer(serializer)) {
        return std::unexpected(make_error_code(RawSocketError::INVALID_SERIALIZER));
    }

    return HandshakeRequest{
        .max_length = static_cast<MaxLengthCode>(length_code),
        .serializer = static_cast<Serializer>(serializer)
    };
}

// Check if handshake is an error response (lower 4 bits of octet2 are zero)
inline bool is_handshake_error(std::span<const uint8_t> data) {
    if (data.size() < HANDSHAKE_SIZE || data[0] != MAGIC_BYTE) {
        return false;
    }
    return (data[1] & 0x0F) == 0;
}

// Decode handshake error response
inline std::expected<HandshakeError, std::error_code> decode_handshake_error(
    std::span<const uint8_t> data
) {
    if (data.size() < HANDSHAKE_SIZE) {
        return std::unexpected(make_error_code(RawSocketError::INSUFFICIENT_DATA));
    }

    if (data[0] != MAGIC_BYTE) {
        return std::unexpected(make_error_code(RawSocketError::INVALID_MAGIC_BYTE));
    }

    uint8_t error_code = (data[1] >> 4) & 0x0F;
    if (error_code == 0 || error_code > 4) {
        return std::unexpected(make_error_code(RawSocketError::HANDSHAKE_FAILED));
    }

    return static_cast<HandshakeError>(error_code);
}

// ============================================================================
// MESSAGE FRAME ENCODING/DECODING
// ============================================================================

// Encode frame header (network byte order / big-endian)
// Format: [RRRRRTTT] [LLLLLLLL] [LLLLLLLL] [LLLLLLLL]
//         Reserved(5)|Type(3)  Length(24-bit, big-endian)
inline std::array<uint8_t, FRAME_HEADER_SIZE> encode_frame_header(
    const FrameHeader& header
) {
    std::array<uint8_t, FRAME_HEADER_SIZE> buffer{};

    // Octet 0: reserved (5 bits) + type (3 bits)
    buffer[0] = static_cast<uint8_t>(header.type) & 0x07;

    // Octets 1-3: 24-bit length in big-endian (network byte order)
    buffer[1] = static_cast<uint8_t>((header.payload_length >> 16) & 0xFF);
    buffer[2] = static_cast<uint8_t>((header.payload_length >> 8) & 0xFF);
    buffer[3] = static_cast<uint8_t>(header.payload_length & 0xFF);

    return buffer;
}

// Decode frame header from network byte order
inline std::expected<FrameHeader, std::error_code> decode_frame_header(
    std::span<const uint8_t> data
) {
    if (data.size() < FRAME_HEADER_SIZE) {
        return std::unexpected(make_error_code(RawSocketError::INSUFFICIENT_DATA));
    }

    // Check reserved bits (upper 5 bits must be zero)
    if ((data[0] & 0xF8) != 0) {
        return std::unexpected(make_error_code(RawSocketError::RESERVED_BITS_SET));
    }

    // Extract frame type (lower 3 bits)
    uint8_t type_value = data[0] & 0x07;
    if (type_value > 2) {  // Only 0, 1, 2 are valid (REGULAR, PING, PONG)
        return std::unexpected(make_error_code(RawSocketError::INVALID_FRAME_TYPE));
    }

    // Extract 24-bit length from big-endian bytes
    uint32_t length = (static_cast<uint32_t>(data[1]) << 16) |
                      (static_cast<uint32_t>(data[2]) << 8) |
                       static_cast<uint32_t>(data[3]);

    return FrameHeader{
        .type = static_cast<FrameType>(type_value),
        .payload_length = length
    };
}

inline std::vector<uint8_t> encode_frame(
    FrameType type,
    std::span<const uint8_t> payload
) {
    std::vector<uint8_t> frame;
    frame.reserve(FRAME_HEADER_SIZE + payload.size());

    FrameHeader header{
        .type = type,
        .payload_length = static_cast<uint32_t>(payload.size())
    };

    auto header_bytes = encode_frame_header(header);
    frame.insert(frame.end(), header_bytes.begin(), header_bytes.end());

    frame.insert(frame.end(), payload.begin(), payload.end());

    return frame;
}

inline bool validate_payload_length(
    uint32_t payload_length,
    MaxLengthCode max_allowed
) {
    uint32_t max_bytes = max_length_to_bytes(max_allowed);
    return payload_length <= max_bytes;
}

inline std::vector<uint8_t> create_ping(std::span<const uint8_t> payload = {}) {
    return encode_frame(FrameType::PING, payload);
}

inline std::vector<uint8_t> create_pong(std::span<const uint8_t> ping_payload) {
    return encode_frame(FrameType::PONG, ping_payload);
}

inline std::vector<uint8_t> create_wamp_message(std::span<const uint8_t> serialized_msg) {
    return encode_frame(FrameType::REGULAR, serialized_msg);
}

} // namespace wamp::rawsocket

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

#pragma once

#include "json.hpp"
#include "msgpack.hpp"
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace wamp {

// The serializer a session speaks. The router core always works on CBOR; a JSON or MessagePack session converts
// whole messages at its edge with wirecodec.
enum class Wire : uint8_t { CBOR, JSON, MSGPACK };

[[nodiscard]] constexpr const char* to_string(Wire wire) {
    switch (wire) {
        case Wire::CBOR:    return "CBOR";
        case Wire::JSON:    return "JSON";
        case Wire::MSGPACK: return "MessagePack";
    }
    return "?";
}

namespace wirecodec {

// Appends the CBOR for a message in `wire` format to `out` (a CBOR message is copied as it is)
[[nodiscard]] inline std::expected<void, std::error_code> to_cbor(Wire wire, std::span<const uint8_t> in,
                                                                  std::vector<uint8_t>& out) {
    switch (wire) {
        case Wire::JSON:
            return jsoncodec::to_cbor({reinterpret_cast<const char*>(in.data()), in.size()}, out);
        case Wire::MSGPACK:
            return msgpackcodec::to_cbor(in, out);
        case Wire::CBOR:
            break;
    }
    out.insert(out.end(), in.begin(), in.end());
    return {};
}

// Appends a CBOR message in `wire` format to `out` (bytes; JSON is text)
[[nodiscard]] inline std::expected<void, std::error_code> from_cbor(Wire wire, std::span<const uint8_t> cbor,
                                                                    std::string& out) {
    switch (wire) {
        case Wire::JSON:
            return jsoncodec::from_cbor(cbor, out);
        case Wire::MSGPACK:
            return msgpackcodec::from_cbor(cbor, out);
        case Wire::CBOR:
            break;
    }
    out.append(reinterpret_cast<const char*>(cbor.data()), cbor.size());
    return {};
}

} // namespace wirecodec
} // namespace wamp

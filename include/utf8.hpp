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

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace wamp {

// True if `s` is well-formed UTF-8 (RFC 3629: no overlong forms, no surrogates, nothing above U+10FFFF)
inline bool valid_utf8(std::string_view s) {
    const auto* p = reinterpret_cast<const uint8_t*>(s.data());
    const auto* end = p + s.size();
    while (p < end) {
        const uint8_t b = *p;
        if (b < 0x80) { ++p; continue; }
        size_t extra;
        uint32_t minimum;
        uint32_t cp;
        if ((b & 0xE0) == 0xC0) { extra = 1; minimum = 0x80; cp = b & 0x1F; }
        else if ((b & 0xF0) == 0xE0) { extra = 2; minimum = 0x800; cp = b & 0x0F; }
        else if ((b & 0xF8) == 0xF0) { extra = 3; minimum = 0x10000; cp = b & 0x07; }
        else return false;
        if (static_cast<size_t>(end - p) <= extra) return false;
        for (size_t i = 1; i <= extra; ++i) {
            if ((p[i] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i] & 0x3F);
        }
        if (cp < minimum || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        p += extra + 1;
    }
    return true;
}

} // namespace wamp

#pragma once

#include "RawCompressor.hpp"
#include "GzipCompressor.hpp"

#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>

namespace packet {

inline bool ends_with(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size()
        && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// open_compressor — choose a runtime compressor based on the output path.
inline std::unique_ptr<Compressor> open_compressor(const std::string& path) {
#ifdef HAS_ZLIB
    if (ends_with(path, ".gz")) {
        return std::make_unique<GzipCompressor>(path);
    }
#endif

    FILE* fp = std::fopen(path.c_str(), "wb");
    if (!fp) {
        throw std::runtime_error("cannot open output: " + path);
    }
    return std::make_unique<RawCompressor>(fp);
}

} // namespace packet

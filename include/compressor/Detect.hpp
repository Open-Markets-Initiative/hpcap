#pragma once

#include "RawCompressor.hpp"
#include "PrefixedCompressor.hpp"
#include "GzipCompressor.hpp"
#include "Bzip2Compressor.hpp"
#include "LzmaCompressor.hpp"
#include "Lz4Compressor.hpp"
#include "ZstdCompressor.hpp"

#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>

namespace packet {

inline bool ends_with(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size()
        && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// open_compressor - choose a runtime compressor based on the output path.
inline std::unique_ptr<Compressor> open_compressor(const std::string& path) {
#ifdef HAS_ZLIB
    if (ends_with(path, ".gz")) {
        return std::make_unique<GzipCompressor>(path);
    }
#endif

#ifdef HAS_BZIP2
    if (ends_with(path, ".bz2")) {
        return std::make_unique<Bzip2Compressor>(path);
    }
#endif

#ifdef HAS_LZMA
    if (ends_with(path, ".xz") || ends_with(path, ".lzma")) {
        return std::make_unique<LzmaCompressor>(path);
    }
#endif

#ifdef HAS_LZ4
    if (ends_with(path, ".lz4")) {
        return std::make_unique<Lz4Compressor>(path);
    }
#endif

#ifdef HAS_ZSTD
    if (ends_with(path, ".zst") || ends_with(path, ".zstd")) {
        return std::make_unique<ZstdCompressor>(path);
    }
#endif

    FILE* fp = std::fopen(path.c_str(), "wb");
    if (!fp) {
        throw std::runtime_error("cannot open output: " + path);
    }
    return std::make_unique<RawCompressor>(fp);
}

} // namespace packet
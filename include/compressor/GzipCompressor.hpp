#pragma once

#ifdef HAS_ZLIB

#include "Compressor.hpp"

#include <stdexcept>
#include <string>
#include <zlib.h>

namespace packet {

// Gzip Compressor — writes gzip-compressed bytes to a file path.
struct GzipCompressor : Compressor {
    gzFile file_ = nullptr;
    bool finished_ = false;

    explicit GzipCompressor(const std::string& path)
        : file_(gzopen(path.c_str(), "wb")) {
        if (!file_) {
            throw std::runtime_error("cannot open gzip output: " + path);
        }
    }

    ~GzipCompressor() override {
        if (file_) {
            gzclose(file_);
        }
    }

    GzipCompressor(const GzipCompressor&) = delete;
    GzipCompressor& operator=(const GzipCompressor&) = delete;

    void write(const void* buf, std::size_t len) override {
        if (finished_) {
            throw std::runtime_error("cannot write after finish");
        }
        if (len == 0) {
            return;
        }

        auto written = gzwrite(file_, buf, static_cast<unsigned int>(len));
        if (written == 0) {
            throw std::runtime_error("gzip write failed");
        }
        if (static_cast<std::size_t>(written) != len) {
            throw std::runtime_error("gzip write truncated");
        }
    }

    void finish() override {
        if (finished_) {
            return;
        }

        auto result = gzflush(file_, Z_FINISH);
        if (result != Z_OK && result != Z_STREAM_END) {
            throw std::runtime_error("gzip flush failed");
        }
        finished_ = true;
    }
};

} // namespace packet

#endif

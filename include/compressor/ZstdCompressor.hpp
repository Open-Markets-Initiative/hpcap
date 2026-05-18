#pragma once

#ifdef HAS_ZSTD

#include "Compressor.hpp"

#include <cstddef>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>
#include <zstd.h>

namespace packet {

// Zstd Compressor - writes zstd-compressed bytes to a file path.
struct ZstdCompressor : Compressor {
    FILE* file_ = nullptr;
    ZSTD_CStream* cstream_ = nullptr;
    std::vector<std::byte> outbuf_;
    bool finished_ = false;

    explicit ZstdCompressor(const std::string& path, int compression_level = 3)
        : file_(std::fopen(path.c_str(), "wb")),
          outbuf_(ZSTD_CStreamOutSize()) {
        if (!file_) {
            throw std::runtime_error("cannot open zstd output: " + path);
        }

        cstream_ = ZSTD_createCStream();
        if (!cstream_) {
            std::fclose(file_);
            file_ = nullptr;
            throw std::runtime_error("ZSTD_createCStream failed");
        }

        auto ret = ZSTD_initCStream(cstream_, compression_level);
        if (ZSTD_isError(ret)) {
            throw std::runtime_error("ZSTD_initCStream failed");
        }
    }

    ~ZstdCompressor() override {
        if (cstream_) {
            ZSTD_freeCStream(cstream_);
        }
        if (file_) {
            std::fclose(file_);
        }
    }

    ZstdCompressor(const ZstdCompressor&) = delete;
    ZstdCompressor& operator=(const ZstdCompressor&) = delete;

    void write(const void* buf, std::size_t len) override {
        if (finished_) {
            throw std::runtime_error("cannot write after finish");
        }
        if (len == 0) {
            return;
        }

        ZSTD_inBuffer input{buf, len, 0};
        while (input.pos < input.size) {
            ZSTD_outBuffer output{outbuf_.data(), outbuf_.size(), 0};
            auto ret = ZSTD_compressStream(cstream_, &output, &input);
            if (ZSTD_isError(ret)) {
                throw std::runtime_error("ZSTD_compressStream failed");
            }
            write_output(outbuf_.data(), output.pos);
        }
    }

    void finish() override {
        if (finished_) {
            return;
        }

        std::size_t remaining = 0;
        do {
            ZSTD_outBuffer output{outbuf_.data(), outbuf_.size(), 0};
            remaining = ZSTD_endStream(cstream_, &output);
            if (ZSTD_isError(remaining)) {
                throw std::runtime_error("ZSTD_endStream failed");
            }
            write_output(outbuf_.data(), output.pos);
        } while (remaining != 0);

        if (std::fflush(file_) != 0) {
            throw std::runtime_error("zstd flush failed");
        }
        finished_ = true;
    }

private:
    void write_output(const void* buf, std::size_t len) {
        if (len == 0) {
            return;
        }
        if (std::fwrite(buf, 1, len, file_) != len) {
            throw std::runtime_error("zstd write failed");
        }
    }
};

} // namespace packet

#endif
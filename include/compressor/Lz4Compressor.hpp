#pragma once

#ifdef HAS_LZ4

#include "Compressor.hpp"

#include <cstddef>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>
#include <lz4frame.h>

namespace packet {

// LZ4 frame Compressor - writes lz4-frame-compressed bytes to a file path.
struct Lz4Compressor : Compressor {
    FILE* file_ = nullptr;
    LZ4F_cctx* ctx_ = nullptr;
    std::vector<std::byte> outbuf_;
    bool finished_ = false;

    explicit Lz4Compressor(const std::string& path)
        : file_(std::fopen(path.c_str(), "wb")),
          outbuf_(LZ4F_compressBound(32768, nullptr)) {
        if (!file_) {
            throw std::runtime_error("cannot open lz4 output: " + path);
        }

        auto err = LZ4F_createCompressionContext(&ctx_, LZ4F_VERSION);
        if (LZ4F_isError(err)) {
            std::fclose(file_);
            file_ = nullptr;
            throw std::runtime_error("LZ4F_createCompressionContext failed");
        }

        auto n = LZ4F_compressBegin(ctx_, outbuf_.data(), outbuf_.size(), nullptr);
        if (LZ4F_isError(n)) {
            throw std::runtime_error("LZ4F_compressBegin failed");
        }
        write_output(outbuf_.data(), n);
    }

    ~Lz4Compressor() override {
        if (ctx_) {
            LZ4F_freeCompressionContext(ctx_);
        }
        if (file_) {
            std::fclose(file_);
        }
    }

    Lz4Compressor(const Lz4Compressor&) = delete;
    Lz4Compressor& operator=(const Lz4Compressor&) = delete;

    void write(const void* buf, std::size_t len) override {
        if (finished_) {
            throw std::runtime_error("cannot write after finish");
        }
        if (len == 0) {
            return;
        }

        auto bound = LZ4F_compressBound(len, nullptr);
        if (outbuf_.size() < bound) {
            outbuf_.resize(bound);
        }

        auto n = LZ4F_compressUpdate(ctx_, outbuf_.data(), outbuf_.size(), buf, len, nullptr);
        if (LZ4F_isError(n)) {
            throw std::runtime_error("LZ4F_compressUpdate failed");
        }
        write_output(outbuf_.data(), n);
    }

    void finish() override {
        if (finished_) {
            return;
        }

        auto n = LZ4F_compressEnd(ctx_, outbuf_.data(), outbuf_.size(), nullptr);
        if (LZ4F_isError(n)) {
            throw std::runtime_error("LZ4F_compressEnd failed");
        }
        write_output(outbuf_.data(), n);
        if (std::fflush(file_) != 0) {
            throw std::runtime_error("lz4 flush failed");
        }
        finished_ = true;
    }

private:
    void write_output(const void* buf, std::size_t len) {
        if (len == 0) {
            return;
        }
        if (std::fwrite(buf, 1, len, file_) != len) {
            throw std::runtime_error("lz4 write failed");
        }
    }
};

} // namespace packet

#endif
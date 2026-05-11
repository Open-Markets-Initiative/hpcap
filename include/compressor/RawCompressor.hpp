#pragma once

#include "Compressor.hpp"

#include <cstdio>
#include <stdexcept>

namespace packet {

// Raw Compressor — writes bytes directly to FILE* without transformation.
struct RawCompressor : Compressor {
    FILE* file_ = nullptr;
    bool finished_ = false;

    explicit RawCompressor(FILE* file) : file_(file) {}

    ~RawCompressor() override {
        if (file_) {
            std::fclose(file_);
        }
    }

    RawCompressor(const RawCompressor&) = delete;
    RawCompressor& operator=(const RawCompressor&) = delete;

    void write(const void* buf, std::size_t len) override {
        if (finished_) {
            throw std::runtime_error("cannot write after finish");
        }
        if (len == 0) {
            return;
        }

        auto written = std::fwrite(buf, 1, len, file_);
        if (written != len) {
            throw std::runtime_error("raw write failed");
        }
    }

    void finish() override {
        if (finished_) {
            return;
        }

        if (std::fflush(file_) != 0) {
            throw std::runtime_error("raw flush failed");
        }
        finished_ = true;
    }
};

} // namespace packet

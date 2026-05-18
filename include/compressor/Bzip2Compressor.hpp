#pragma once

#ifdef HAS_BZIP2

#include "Compressor.hpp"

#include <cstdio>
#include <limits>
#include <stdexcept>
#include <string>
#include <bzlib.h>

namespace packet {

// Bzip2 Compressor - writes bzip2-compressed bytes to a file path.
struct Bzip2Compressor : Compressor {
    FILE* file_ = nullptr;
    BZFILE* bzfile_ = nullptr;
    int bzerror_ = BZ_OK;
    bool finished_ = false;

    explicit Bzip2Compressor(const std::string& path)
        : file_(std::fopen(path.c_str(), "wb")) {
        if (!file_) {
            throw std::runtime_error("cannot open bzip2 output: " + path);
        }

        bzfile_ = BZ2_bzWriteOpen(&bzerror_, file_, 9, 0, 0);
        if (bzerror_ != BZ_OK || !bzfile_) {
            std::fclose(file_);
            file_ = nullptr;
            throw std::runtime_error("BZ2_bzWriteOpen failed");
        }
    }

    ~Bzip2Compressor() override {
        if (bzfile_) {
            int abandon = finished_ ? 0 : 1;
            BZ2_bzWriteClose(&bzerror_, bzfile_, abandon, nullptr, nullptr);
        }
        if (file_) {
            std::fclose(file_);
        }
    }

    Bzip2Compressor(const Bzip2Compressor&) = delete;
    Bzip2Compressor& operator=(const Bzip2Compressor&) = delete;

    void write(const void* buf, std::size_t len) override {
        if (finished_) {
            throw std::runtime_error("cannot write after finish");
        }
        if (len == 0) {
            return;
        }
        if (len > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
            throw std::runtime_error("bzip2 write too large");
        }

        BZ2_bzWrite(&bzerror_, bzfile_, const_cast<void*>(buf), static_cast<int>(len));
        if (bzerror_ != BZ_OK) {
            throw std::runtime_error("BZ2_bzWrite failed");
        }
    }

    void finish() override {
        if (finished_) {
            return;
        }

        BZ2_bzWriteClose(&bzerror_, bzfile_, 0, nullptr, nullptr);
        bzfile_ = nullptr;
        if (bzerror_ != BZ_OK) {
            throw std::runtime_error("BZ2_bzWriteClose failed");
        }
        if (std::fflush(file_) != 0) {
            throw std::runtime_error("bzip2 flush failed");
        }
        finished_ = true;
    }
};

} // namespace packet

#endif
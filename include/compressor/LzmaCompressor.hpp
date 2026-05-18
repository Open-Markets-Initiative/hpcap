#pragma once

#ifdef HAS_LZMA

#include "Compressor.hpp"

#include <array>
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <lzma.h>

namespace packet {

// LZMA/XZ Compressor - writes xz-compressed bytes to a file path.
struct LzmaCompressor : Compressor {
    FILE* file_ = nullptr;
    lzma_stream stream_ = LZMA_STREAM_INIT;
    std::array<std::uint8_t, 32768> outbuf_{};
    bool finished_ = false;

    explicit LzmaCompressor(const std::string& path)
        : file_(std::fopen(path.c_str(), "wb")) {
        if (!file_) {
            throw std::runtime_error("cannot open lzma output: " + path);
        }
        if (lzma_easy_encoder(&stream_, 6, LZMA_CHECK_CRC64) != LZMA_OK) {
            std::fclose(file_);
            file_ = nullptr;
            throw std::runtime_error("lzma_easy_encoder failed");
        }
    }

    ~LzmaCompressor() override {
        lzma_end(&stream_);
        if (file_) {
            std::fclose(file_);
        }
    }

    LzmaCompressor(const LzmaCompressor&) = delete;
    LzmaCompressor& operator=(const LzmaCompressor&) = delete;

    void write(const void* buf, std::size_t len) override {
        if (finished_) {
            throw std::runtime_error("cannot write after finish");
        }
        if (len == 0) {
            return;
        }

        stream_.next_in = static_cast<const std::uint8_t*>(buf);
        stream_.avail_in = len;
        pump(LZMA_RUN);
    }

    void finish() override {
        if (finished_) {
            return;
        }

        stream_.next_in = nullptr;
        stream_.avail_in = 0;
        pump(LZMA_FINISH);
        if (std::fflush(file_) != 0) {
            throw std::runtime_error("lzma flush failed");
        }
        finished_ = true;
    }

private:
    void pump(lzma_action action) {
        lzma_ret ret = LZMA_OK;
        do {
            stream_.next_out = outbuf_.data();
            stream_.avail_out = outbuf_.size();

            ret = lzma_code(&stream_, action);
            if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
                throw std::runtime_error("lzma_code failed");
            }

            auto written = outbuf_.size() - stream_.avail_out;
            if (written != 0 && std::fwrite(outbuf_.data(), 1, written, file_) != written) {
                throw std::runtime_error("lzma write failed");
            }
        } while (stream_.avail_in != 0 || (action == LZMA_FINISH && ret != LZMA_STREAM_END));
    }
};

} // namespace packet

#endif
#pragma once

#include "Compressor.hpp"

#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>

namespace packet {

// Prefixed Compressor - writes a small prefix before delegating to an inner sink.
struct PrefixedCompressor : Compressor {
    std::unique_ptr<Compressor> inner_;
    std::vector<std::byte> prefix_;
    bool prefix_written_ = false;

    PrefixedCompressor(std::unique_ptr<Compressor> inner,
                       const void* prefix, std::size_t len)
        : inner_(std::move(inner)), prefix_(len) {
        if (len != 0) {
            std::memcpy(prefix_.data(), prefix, len);
        }
    }

    PrefixedCompressor(const PrefixedCompressor&) = delete;
    PrefixedCompressor& operator=(const PrefixedCompressor&) = delete;

    void write(const void* buf, std::size_t len) override {
        write_prefix();
        inner_->write(buf, len);
    }

    void finish() override {
        write_prefix();
        inner_->finish();
    }

private:
    void write_prefix() {
        if (prefix_written_) {
            return;
        }
        prefix_written_ = true;
        if (!prefix_.empty()) {
            inner_->write(prefix_.data(), prefix_.size());
        }
    }
};

} // namespace packet
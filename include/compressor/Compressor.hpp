#pragma once

#include <cstddef>

namespace packet {

// Abstract Compressor — writes bytes to a sink, optionally compressing them.
struct Compressor {
    virtual ~Compressor() = default;
    virtual void write(const void* buf, std::size_t len) = 0;
    virtual void finish() = 0;
};

} // namespace packet

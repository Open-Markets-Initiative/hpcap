#pragma once

// Polymorphic pcap packet source with transparent decompression
// Supports: classic pcap (micro/nanosecond), pcap-ng (SHB/IDB/EPB)
// Compression: raw, gzip, bzip2, lzma/xz, lz4, zstd (each conditional on HAS_*)
// Decompressors are composable — each reads from any decompressor source

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef HAS_ZLIB
#include <zlib.h>
#endif

#ifdef HAS_BZIP2
#include <bzlib.h>
#endif

#ifdef HAS_LZMA
#include <lzma.h>
#endif

#ifdef HAS_LZ4
#include <lz4frame.h>
#endif

#ifdef HAS_ZSTD
#include <zstd.h>
#endif

namespace packet {

// ---------------------------------------------------------------------------
// Abstract packet source — anything that produces packets in time order
// ---------------------------------------------------------------------------

struct pcap_source {
    virtual ~pcap_source() = default;
    virtual bool advance() = 0;
    virtual std::uint64_t timestamp_ns() const = 0;
    virtual const std::byte* data() const = 0;
    virtual std::uint32_t length() const = 0;
    virtual bool done() const = 0;
};

// ---------------------------------------------------------------------------
// Abstract decompressor — reads decompressed bytes from a source
// ---------------------------------------------------------------------------

struct decompressor {
    virtual ~decompressor() = default;
    virtual std::size_t read(void* buf, std::size_t len) = 0;
    virtual bool eof() const = 0;
};

// ---------------------------------------------------------------------------
// Raw decompressor — reads directly from FILE*
// This is the only decompressor that touches FILE*. All others read from
// a decompressor source, making the whole stack composable.
// ---------------------------------------------------------------------------

struct raw_decompressor : decompressor {
    FILE* file_;
    bool at_eof_ = false;

    explicit raw_decompressor(FILE* fp) : file_(fp) {}

    ~raw_decompressor() override {
        if (file_) std::fclose(file_);
    }

    raw_decompressor(const raw_decompressor&) = delete;
    raw_decompressor& operator=(const raw_decompressor&) = delete;

    std::size_t read(void* buf, std::size_t len) override {
        auto n = std::fread(buf, 1, len, file_);
        if (n == 0) at_eof_ = true;
        return n;
    }

    bool eof() const override { return at_eof_; }
};

// ---------------------------------------------------------------------------
// Prefixed decompressor — replays a small prefix then delegates to inner source.
// Used after peeking magic bytes for format detection.
// ---------------------------------------------------------------------------

struct prefixed_decompressor : decompressor {
    std::unique_ptr<decompressor> inner_;
    unsigned char prefix_[8];
    std::size_t prefix_len_;
    std::size_t prefix_pos_ = 0;

    prefixed_decompressor(std::unique_ptr<decompressor> inner,
                          const void* prefix, std::size_t len)
        : inner_(std::move(inner)), prefix_len_(len) {
        std::memcpy(prefix_, prefix, len);
    }

    prefixed_decompressor(const prefixed_decompressor&) = delete;
    prefixed_decompressor& operator=(const prefixed_decompressor&) = delete;

    std::size_t read(void* buf, std::size_t len) override {
        auto* out = static_cast<unsigned char*>(buf);
        std::size_t total = 0;
        while (total < len && prefix_pos_ < prefix_len_) {
            out[total++] = prefix_[prefix_pos_++];
        }
        if (total < len) {
            total += inner_->read(out + total, len - total);
        }
        return total;
    }

    bool eof() const override {
        return prefix_pos_ >= prefix_len_ && inner_->eof();
    }
};

// ---------------------------------------------------------------------------
// Gzip decompressor (conditional on HAS_ZLIB)
// Reads compressed bytes from any decompressor source
// ---------------------------------------------------------------------------

#ifdef HAS_ZLIB
struct gzip_decompressor : decompressor {
    std::unique_ptr<decompressor> source_;
    z_stream stream_{};
    std::vector<Bytef> inbuf_;
    bool finished_ = false;

    explicit gzip_decompressor(std::unique_ptr<decompressor> source,
                               std::size_t inbuf_size = 32768)
        : source_(std::move(source)), inbuf_(inbuf_size) {
        stream_.zalloc = Z_NULL;
        stream_.zfree = Z_NULL;
        stream_.opaque = Z_NULL;
        stream_.avail_in = 0;
        stream_.next_in = Z_NULL;
        if (inflateInit2(&stream_, 15 + 16) != Z_OK)
            throw std::runtime_error("inflateInit2 failed");
    }

    ~gzip_decompressor() override { inflateEnd(&stream_); }

    gzip_decompressor(const gzip_decompressor&) = delete;
    gzip_decompressor& operator=(const gzip_decompressor&) = delete;

    std::size_t read(void* buf, std::size_t len) override {
        stream_.next_out = static_cast<Bytef*>(buf);
        stream_.avail_out = static_cast<uInt>(len);
        while (stream_.avail_out > 0 && !finished_) {
            if (stream_.avail_in == 0) {
                auto n = source_->read(inbuf_.data(), inbuf_.size());
                if (n == 0) break;
                stream_.next_in = inbuf_.data();
                stream_.avail_in = static_cast<uInt>(n);
            }
            int ret = inflate(&stream_, Z_NO_FLUSH);
            if (ret == Z_STREAM_END) { finished_ = true; break; }
            if (ret != Z_OK) throw std::runtime_error("inflate error");
        }
        return len - stream_.avail_out;
    }

    bool eof() const override { return finished_; }
};
#endif

// ---------------------------------------------------------------------------
// Bzip2 decompressor (conditional on HAS_BZIP2)
// ---------------------------------------------------------------------------

#ifdef HAS_BZIP2
struct bzip2_decompressor : decompressor {
    std::unique_ptr<decompressor> source_;
    bz_stream stream_{};
    std::vector<char> inbuf_;
    bool finished_ = false;

    explicit bzip2_decompressor(std::unique_ptr<decompressor> source,
                                std::size_t inbuf_size = 32768)
        : source_(std::move(source)), inbuf_(inbuf_size) {
        stream_.bzalloc = nullptr;
        stream_.bzfree = nullptr;
        stream_.opaque = nullptr;
        if (BZ2_bzDecompressInit(&stream_, 0, 0) != BZ_OK)
            throw std::runtime_error("BZ2_bzDecompressInit failed");
    }

    ~bzip2_decompressor() override { BZ2_bzDecompressEnd(&stream_); }

    bzip2_decompressor(const bzip2_decompressor&) = delete;
    bzip2_decompressor& operator=(const bzip2_decompressor&) = delete;

    std::size_t read(void* buf, std::size_t len) override {
        stream_.next_out = static_cast<char*>(buf);
        stream_.avail_out = static_cast<unsigned int>(len);
        while (stream_.avail_out > 0 && !finished_) {
            if (stream_.avail_in == 0) {
                auto n = source_->read(inbuf_.data(), inbuf_.size());
                if (n == 0) break;
                stream_.next_in = inbuf_.data();
                stream_.avail_in = static_cast<unsigned int>(n);
            }
            int ret = BZ2_bzDecompress(&stream_);
            if (ret == BZ_STREAM_END) { finished_ = true; break; }
            if (ret != BZ_OK) throw std::runtime_error("BZ2_bzDecompress error");
        }
        return len - stream_.avail_out;
    }

    bool eof() const override { return finished_; }
};
#endif

// ---------------------------------------------------------------------------
// LZMA/XZ decompressor (conditional on HAS_LZMA)
// ---------------------------------------------------------------------------

#ifdef HAS_LZMA
struct lzma_decompressor : decompressor {
    std::unique_ptr<decompressor> source_;
    lzma_stream stream_;
    std::vector<std::uint8_t> inbuf_;
    bool finished_ = false;

    explicit lzma_decompressor(std::unique_ptr<decompressor> source,
                               std::size_t inbuf_size = 32768)
        : source_(std::move(source)), stream_(LZMA_STREAM_INIT), inbuf_(inbuf_size) {
        if (lzma_stream_decoder(&stream_, UINT64_MAX, 0) != LZMA_OK)
            throw std::runtime_error("lzma_stream_decoder failed");
    }

    ~lzma_decompressor() override { lzma_end(&stream_); }

    lzma_decompressor(const lzma_decompressor&) = delete;
    lzma_decompressor& operator=(const lzma_decompressor&) = delete;

    std::size_t read(void* buf, std::size_t len) override {
        stream_.next_out = static_cast<std::uint8_t*>(buf);
        stream_.avail_out = len;
        while (stream_.avail_out > 0 && !finished_) {
            if (stream_.avail_in == 0) {
                auto n = source_->read(inbuf_.data(), inbuf_.size());
                if (n == 0) {
                    auto ret = lzma_code(&stream_, LZMA_FINISH);
                    if (ret == LZMA_STREAM_END) finished_ = true;
                    break;
                }
                stream_.next_in = inbuf_.data();
                stream_.avail_in = n;
            }
            auto ret = lzma_code(&stream_, LZMA_RUN);
            if (ret == LZMA_STREAM_END) { finished_ = true; break; }
            if (ret != LZMA_OK) throw std::runtime_error("lzma_code error");
        }
        return len - stream_.avail_out;
    }

    bool eof() const override { return finished_; }
};
#endif

// ---------------------------------------------------------------------------
// LZ4 frame decompressor (conditional on HAS_LZ4)
// ---------------------------------------------------------------------------

#ifdef HAS_LZ4
struct lz4_decompressor : decompressor {
    std::unique_ptr<decompressor> source_;
    LZ4F_dctx* ctx_ = nullptr;
    std::vector<std::byte> inbuf_;
    std::size_t in_pos_ = 0;
    std::size_t in_size_ = 0;
    bool finished_ = false;

    explicit lz4_decompressor(std::unique_ptr<decompressor> source,
                              std::size_t inbuf_size = 32768)
        : source_(std::move(source)), inbuf_(inbuf_size) {
        auto err = LZ4F_createDecompressionContext(&ctx_, LZ4F_VERSION);
        if (LZ4F_isError(err))
            throw std::runtime_error("LZ4F_createDecompressionContext failed");
    }

    ~lz4_decompressor() override {
        if (ctx_) LZ4F_freeDecompressionContext(ctx_);
    }

    lz4_decompressor(const lz4_decompressor&) = delete;
    lz4_decompressor& operator=(const lz4_decompressor&) = delete;

    std::size_t read(void* buf, std::size_t len) override {
        auto* out = static_cast<std::byte*>(buf);
        std::size_t total_out = 0;
        while (total_out < len && !finished_) {
            if (in_pos_ >= in_size_) {
                in_size_ = source_->read(inbuf_.data(), inbuf_.size());
                in_pos_ = 0;
                if (in_size_ == 0) { finished_ = true; break; }
            }
            std::size_t dst_size = len - total_out;
            std::size_t src_size = in_size_ - in_pos_;
            auto ret = LZ4F_decompress(ctx_, out + total_out, &dst_size,
                                        inbuf_.data() + in_pos_, &src_size, nullptr);
            if (LZ4F_isError(ret))
                throw std::runtime_error("LZ4F_decompress error");
            total_out += dst_size;
            in_pos_ += src_size;
            if (ret == 0) { finished_ = true; break; }
        }
        return total_out;
    }

    bool eof() const override { return finished_; }
};
#endif

// ---------------------------------------------------------------------------
// Zstd decompressor (conditional on HAS_ZSTD)
// ---------------------------------------------------------------------------

#ifdef HAS_ZSTD
struct zstd_decompressor : decompressor {
    std::unique_ptr<decompressor> source_;
    ZSTD_DStream* dstream_ = nullptr;
    std::vector<std::byte> inbuf_;
    ZSTD_inBuffer input_{};
    bool finished_ = false;

    explicit zstd_decompressor(std::unique_ptr<decompressor> source,
                               std::size_t inbuf_size = 32768)
        : source_(std::move(source)), inbuf_(inbuf_size) {
        dstream_ = ZSTD_createDStream();
        if (!dstream_)
            throw std::runtime_error("ZSTD_createDStream failed");
        ZSTD_initDStream(dstream_);
    }

    ~zstd_decompressor() override {
        if (dstream_) ZSTD_freeDStream(dstream_);
    }

    zstd_decompressor(const zstd_decompressor&) = delete;
    zstd_decompressor& operator=(const zstd_decompressor&) = delete;

    std::size_t read(void* buf, std::size_t len) override {
        ZSTD_outBuffer output{buf, len, 0};
        while (output.pos < output.size && !finished_) {
            if (input_.pos >= input_.size) {
                auto n = source_->read(inbuf_.data(), inbuf_.size());
                if (n == 0) { finished_ = true; break; }
                input_ = {inbuf_.data(), n, 0};
            }
            auto ret = ZSTD_decompressStream(dstream_, &output, &input_);
            if (ZSTD_isError(ret))
                throw std::runtime_error("ZSTD_decompressStream error");
            if (ret == 0) { finished_ = true; break; }
        }
        return output.pos;
    }

    bool eof() const override { return finished_; }
};
#endif

// ---------------------------------------------------------------------------
// detect_and_wrap — peek magic bytes from any decompressor, wrap if compressed.
// Works on any source: raw files, zip entries, or chained decompressors.
// ---------------------------------------------------------------------------

inline std::unique_ptr<decompressor>
detect_and_wrap(std::unique_ptr<decompressor> source) {
    unsigned char magic[6]{};
    auto n = source->read(magic, 6);

    // Prepend the peeked bytes back so the next reader sees the full stream
    auto prefixed = std::make_unique<prefixed_decompressor>(
        std::move(source), magic, n);

#ifdef HAS_ZLIB
    if (n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b)
        return std::make_unique<gzip_decompressor>(std::move(prefixed));
#endif

#ifdef HAS_BZIP2
    if (n >= 2 && magic[0] == 0x42 && magic[1] == 0x5a)
        return std::make_unique<bzip2_decompressor>(std::move(prefixed));
#endif

#ifdef HAS_LZMA
    if (n >= 6 && magic[0] == 0xfd && magic[1] == 0x37 && magic[2] == 0x7a
               && magic[3] == 0x58 && magic[4] == 0x5a && magic[5] == 0x00)
        return std::make_unique<lzma_decompressor>(std::move(prefixed));
#endif

#ifdef HAS_LZ4
    if (n >= 4 && magic[0] == 0x04 && magic[1] == 0x22
               && magic[2] == 0x4d && magic[3] == 0x18)
        return std::make_unique<lz4_decompressor>(std::move(prefixed));
#endif

#ifdef HAS_ZSTD
    if (n >= 4 && magic[0] == 0x28 && magic[1] == 0xb5
               && magic[2] == 0x2f && magic[3] == 0xfd)
        return std::make_unique<zstd_decompressor>(std::move(prefixed));
#endif

    // Not compressed — return with prefix replayed (pcap header bytes)
    return prefixed;
}

// ---------------------------------------------------------------------------
// open_decompressor — open a file path with auto-detected decompression
// ---------------------------------------------------------------------------

inline std::unique_ptr<decompressor> open_decompressor(const std::string& path) {
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) throw std::runtime_error("cannot open: " + path);
    return detect_and_wrap(std::make_unique<raw_decompressor>(fp));
}

// ---------------------------------------------------------------------------
// Pcap buffer — decompressed byte buffer with refill/shift
// ---------------------------------------------------------------------------

constexpr std::size_t default_buffer_size = 65536;

class pcap_buffer {
    std::unique_ptr<decompressor> source_;
    std::vector<std::byte> buf_;
    std::size_t pos_ = 0;
    std::size_t valid_ = 0;

public:
    explicit pcap_buffer(std::unique_ptr<decompressor> source,
                         std::size_t buf_size = default_buffer_size)
        : source_(std::move(source)), buf_(buf_size) {}

    pcap_buffer(const pcap_buffer&) = delete;
    pcap_buffer& operator=(const pcap_buffer&) = delete;
    pcap_buffer(pcap_buffer&&) = default;
    pcap_buffer& operator=(pcap_buffer&&) = default;

    bool ensure(std::size_t n) {
        if (n > buf_.size()) return false;
        while (available() < n) {
            if (!refill()) return false;
        }
        return true;
    }

    std::size_t available() const { return valid_ - pos_; }
    const std::byte* data() const { return buf_.data() + pos_; }
    void consume(std::size_t n) { pos_ += n; }

private:
    bool refill() {
        std::size_t remaining = valid_ - pos_;
        if (pos_ > 0) {
            if (remaining > 0)
                std::memmove(buf_.data(), buf_.data() + pos_, remaining);
            pos_ = 0;
            valid_ = remaining;
        }
        std::size_t space = buf_.size() - valid_;
        if (space == 0) return false;
        auto got = source_->read(buf_.data() + valid_, space);
        valid_ += got;
        return got > 0;
    }
};

// ---------------------------------------------------------------------------
// Pcap file reader — reads one pcap file, producing packets sequentially
// ---------------------------------------------------------------------------

struct pcap_file : pcap_source {

    // Construct from file path (auto-detects compression + pcap format)
    explicit pcap_file(const std::string& path,
                       std::size_t buf_size = default_buffer_size)
        : buffer_(open_decompressor(path), buf_size) {
        parse_file_header();
    }

    // Construct from pre-built decompressor (zip entries, chained decompressors)
    explicit pcap_file(std::unique_ptr<decompressor> dec,
                       std::size_t buf_size = default_buffer_size)
        : buffer_(std::move(dec), buf_size) {
        parse_file_header();
    }

    pcap_file(const pcap_file&) = delete;
    pcap_file& operator=(const pcap_file&) = delete;
    pcap_file(pcap_file&&) = default;
    pcap_file& operator=(pcap_file&&) = default;

    bool advance() override {
        if (done_) return false;
        return is_pcapng_ ? advance_pcapng() : advance_classic();
    }

    std::uint64_t timestamp_ns() const override { return ts_ns_; }
    const std::byte* data() const override { return pkt_data_; }
    std::uint32_t length() const override { return pkt_len_; }
    bool done() const override { return done_; }

private:
    pcap_buffer buffer_;
    bool swap_bytes_ = false;
    bool nanosecond_ts_ = false;
    bool is_pcapng_ = false;
    bool done_ = false;

    // Current packet state
    std::uint64_t ts_ns_ = 0;
    const std::byte* pkt_data_ = nullptr;
    std::uint32_t pkt_len_ = 0;

    // Pcap-ng interface tracking
    struct interface_info {
        std::uint64_t ts_resol = 1000000;  // default: microsecond (10^6)
    };
    std::vector<interface_info> interfaces_;

    // --- Endian helpers ---
    std::uint16_t fix16(std::uint16_t v) const { return swap_bytes_ ? std::byteswap(v) : v; }
    std::uint32_t fix32(std::uint32_t v) const { return swap_bytes_ ? std::byteswap(v) : v; }
    std::uint64_t fix64(std::uint64_t v) const { return swap_bytes_ ? std::byteswap(v) : v; }

    // --- Header parsing ---

    void parse_file_header() {
        if (!buffer_.ensure(4))
            throw std::runtime_error("file too short for pcap header");

        std::uint32_t magic;
        std::memcpy(&magic, buffer_.data(), 4);

        if (magic == 0x0a0d0d0a) {
            is_pcapng_ = true;
            parse_pcapng_shb();
        } else {
            parse_classic_header(magic);
        }
    }

    void parse_classic_header(std::uint32_t magic) {
        switch (magic) {
        case 0xa1b2c3d4: swap_bytes_ = false; nanosecond_ts_ = false; break;
        case 0xd4c3b2a1: swap_bytes_ = true;  nanosecond_ts_ = false; break;
        case 0xa1b23c4d: swap_bytes_ = false; nanosecond_ts_ = true;  break;
        case 0x4d3cb2a1: swap_bytes_ = true;  nanosecond_ts_ = true;  break;
        default:
            throw std::runtime_error("invalid pcap magic number");
        }
        if (!buffer_.ensure(24))
            throw std::runtime_error("truncated pcap global header");
        buffer_.consume(24);
    }

    // --- Classic pcap packet iteration ---

    bool advance_classic() {
        if (!buffer_.ensure(16)) { done_ = true; return false; }

        std::uint32_t ts_sec, ts_usec, caplen;
        std::memcpy(&ts_sec,  buffer_.data(),      4);
        std::memcpy(&ts_usec, buffer_.data() + 4,  4);
        std::memcpy(&caplen,  buffer_.data() + 8,  4);
        buffer_.consume(16);

        ts_sec  = fix32(ts_sec);
        ts_usec = fix32(ts_usec);
        caplen  = fix32(caplen);

        if (!buffer_.ensure(caplen)) { done_ = true; return false; }

        pkt_data_ = buffer_.data();
        pkt_len_  = caplen;

        if (nanosecond_ts_) {
            ts_ns_ = static_cast<std::uint64_t>(ts_sec) * 1000000000ULL + ts_usec;
        } else {
            ts_ns_ = static_cast<std::uint64_t>(ts_sec) * 1000000000ULL
                   + static_cast<std::uint64_t>(ts_usec) * 1000ULL;
        }

        buffer_.consume(caplen);
        return true;
    }

    // --- Pcap-ng parsing ---

    void parse_pcapng_shb() {
        if (!buffer_.ensure(12))
            throw std::runtime_error("truncated pcap-ng SHB");

        std::uint32_t bom;
        std::memcpy(&bom, buffer_.data() + 8, 4);

        if (bom == 0x1a2b3c4d) {
            swap_bytes_ = false;
        } else if (bom == 0x4d3c2b1a) {
            swap_bytes_ = true;
        } else {
            throw std::runtime_error("invalid pcap-ng byte order magic");
        }

        std::uint32_t block_len;
        std::memcpy(&block_len, buffer_.data() + 4, 4);
        block_len = fix32(block_len);

        if (!buffer_.ensure(block_len))
            throw std::runtime_error("truncated pcap-ng SHB block");
        buffer_.consume(block_len);
    }

    bool advance_pcapng() {
        while (true) {
            if (!buffer_.ensure(8)) { done_ = true; return false; }

            std::uint32_t block_type, block_len;
            std::memcpy(&block_type, buffer_.data(),     4);
            std::memcpy(&block_len,  buffer_.data() + 4, 4);

            block_type = fix32(block_type);
            block_len  = fix32(block_len);

            if (block_len < 12) { done_ = true; return false; }
            if (!buffer_.ensure(block_len)) { done_ = true; return false; }

            const std::byte* block = buffer_.data();

            switch (block_type) {
            case 0x0a0d0d0a:  // SHB — new section
                parse_pcapng_new_section(block);
                break;

            case 1:  // IDB — Interface Description Block
                parse_pcapng_idb(block, block_len);
                break;

            case 6: {  // EPB — Enhanced Packet Block
                if (parse_pcapng_epb(block, block_len)) {
                    buffer_.consume(block_len);
                    return true;
                }
                break;
            }

            default:
                break;
            }

            buffer_.consume(block_len);
        }
    }

    void parse_pcapng_new_section(const std::byte* block) {
        std::uint32_t bom;
        std::memcpy(&bom, block + 8, 4);
        if (bom == 0x1a2b3c4d) swap_bytes_ = false;
        else if (bom == 0x4d3c2b1a) swap_bytes_ = true;
        interfaces_.clear();
    }

    void parse_pcapng_idb(const std::byte* block, std::uint32_t block_len) {
        interface_info iface;
        if (block_len > 16 + 4) {
            parse_idb_options(block + 16, block_len - 16 - 4, iface);
        }
        interfaces_.push_back(iface);
    }

    void parse_idb_options(const std::byte* opts, std::uint32_t opts_len,
                           interface_info& iface) {
        std::size_t pos = 0;
        while (pos + 4 <= opts_len) {
            std::uint16_t opt_code, opt_len;
            std::memcpy(&opt_code, opts + pos,     2);
            std::memcpy(&opt_len,  opts + pos + 2, 2);
            opt_code = fix16(opt_code);
            opt_len  = fix16(opt_len);
            pos += 4;

            if (opt_code == 0) break;
            if (pos + opt_len > opts_len) break;

            if (opt_code == 9 && opt_len == 1) {
                auto val = static_cast<std::uint8_t>(opts[pos]);
                if (val & 0x80) {
                    iface.ts_resol = 1ULL << (val & 0x7f);
                } else {
                    iface.ts_resol = 1;
                    for (std::uint8_t i = 0; i < val; i++)
                        iface.ts_resol *= 10;
                }
            }

            pos += opt_len;
            pos = (pos + 3) & ~std::size_t{3};
        }
    }

    bool parse_pcapng_epb(const std::byte* block, [[maybe_unused]] std::uint32_t block_len) {
        std::uint32_t iface_id, ts_high, ts_low, caplen;
        std::memcpy(&iface_id, block + 8,  4);
        std::memcpy(&ts_high,  block + 12, 4);
        std::memcpy(&ts_low,   block + 16, 4);
        std::memcpy(&caplen,   block + 20, 4);

        iface_id = fix32(iface_id);
        ts_high  = fix32(ts_high);
        ts_low   = fix32(ts_low);
        caplen   = fix32(caplen);

        pkt_data_ = block + 28;
        pkt_len_  = caplen;

        std::uint64_t ts = (static_cast<std::uint64_t>(ts_high) << 32) | ts_low;
        std::uint64_t resol = (iface_id < interfaces_.size())
                            ? interfaces_[iface_id].ts_resol
                            : 1000000ULL;

        if (resol == 1000000000ULL) {
            ts_ns_ = ts;
        } else if (resol == 1000000ULL) {
            ts_ns_ = ts * 1000ULL;
        } else if (resol > 0) {
            ts_ns_ = static_cast<std::uint64_t>(
                static_cast<double>(ts) * 1e9 / static_cast<double>(resol));
        } else {
            ts_ns_ = 0;
        }

        return true;
    }
};

} // namespace packet
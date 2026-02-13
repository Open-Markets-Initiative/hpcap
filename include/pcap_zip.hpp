#pragma once

// Zip archive support for pcap iteration
// Adapts libzip entry streams to the decompressor interface.
// Handles double-compressed entries (e.g. .pcap.zst inside .zip) via detect_and_wrap().
// Entirely conditional on HAS_LIBZIP

#ifdef HAS_LIBZIP

#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <zip.h>

#include "pcap_source.hpp"

namespace packet {

// ---------------------------------------------------------------------------
// Zip entry decompressor — reads decompressed bytes from a zip entry.
// libzip handles zip-level compression (deflate, etc.) — we get the entry's
// raw content, which may itself be compressed (e.g. a .pcap.zst file).
// ---------------------------------------------------------------------------

struct zip_entry_decompressor : decompressor {
    std::shared_ptr<zip_t> archive_;
    zip_file_t* entry_ = nullptr;
    bool finished_ = false;

    zip_entry_decompressor(std::shared_ptr<zip_t> archive, zip_uint64_t index)
        : archive_(std::move(archive)) {
        entry_ = zip_fopen_index(archive_.get(), index, 0);
        if (!entry_)
            throw std::runtime_error("zip_fopen_index failed");
    }

    ~zip_entry_decompressor() override {
        if (entry_) zip_fclose(entry_);
    }

    zip_entry_decompressor(const zip_entry_decompressor&) = delete;
    zip_entry_decompressor& operator=(const zip_entry_decompressor&) = delete;

    std::size_t read(void* buf, std::size_t len) override {
        if (finished_) return 0;
        auto n = zip_fread(entry_, buf, len);
        if (n < 0) throw std::runtime_error("zip_fread failed");
        if (n == 0) finished_ = true;
        return static_cast<std::size_t>(n);
    }

    bool eof() const override { return finished_; }
};

// ---------------------------------------------------------------------------
// Extension matching — strips compression suffixes to find base pcap extension
// ---------------------------------------------------------------------------

inline bool is_pcap_entry(const std::string& name) {
    auto base = name;

    // Strip known compression suffixes
    constexpr const char* suffixes[] = {
        ".zst", ".gz", ".bz2", ".xz", ".lz4", ".lzo", ".Z"
    };
    for (const auto* suffix : suffixes) {
        auto slen = std::strlen(suffix);
        if (base.size() > slen && base.substr(base.size() - slen) == suffix) {
            base = base.substr(0, base.size() - slen);
            break;
        }
    }

    // Check for pcap base extension
    if (base.size() >= 5 && base.substr(base.size() - 5) == ".pcap") return true;
    if (base.size() >= 4 && base.substr(base.size() - 4) == ".cap")  return true;
    return false;
}

// ---------------------------------------------------------------------------
// Open all pcap entries from a zip archive as pcap_source objects.
// Each entry goes through detect_and_wrap() so inner compression
// (e.g. .pcap.zst) is handled transparently.
// ---------------------------------------------------------------------------

inline std::vector<std::unique_ptr<pcap_source>>
open_zip_pcaps(const std::string& path) {
    int err = 0;
    auto* raw = zip_open(path.c_str(), ZIP_RDONLY, &err);
    if (!raw)
        throw std::runtime_error("zip_open failed: " + path);

    // Shared ownership — archive stays open until all entry decompressors are done
    auto archive = std::shared_ptr<zip_t>(raw, [](zip_t* z) { zip_close(z); });

    auto num_entries = zip_get_num_entries(archive.get(), 0);
    std::vector<std::unique_ptr<pcap_source>> sources;

    for (zip_int64_t i = 0; i < num_entries; i++) {
        const char* entry_name = zip_get_name(
            archive.get(), static_cast<zip_uint64_t>(i), 0);
        if (!entry_name) continue;
        if (!is_pcap_entry(entry_name)) continue;

        // Create zip entry decompressor, then detect inner compression
        auto entry_dec = std::make_unique<zip_entry_decompressor>(
            archive, static_cast<zip_uint64_t>(i));
        auto final_dec = detect_and_wrap(std::move(entry_dec));
        sources.push_back(std::make_unique<pcap_file>(std::move(final_dec)));
    }

    return sources;
}

} // namespace packet

#endif // HAS_LIBZIP
#pragma once

// Time-ordered merge iterator over multiple pcap sources
// Expands glob patterns, applies per-source nanosecond offsets,
// and dispatches .zip files to the zip handler when HAS_LIBZIP is defined.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <queue>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <glob.h>

#include "pcap_source.hpp"

#ifdef HAS_LIBZIP
#include "pcap_zip.hpp"
#endif

namespace packet {

struct pcap_iterator : pcap_source {

    struct source_entry {
        std::unique_ptr<pcap_source> source;
        std::int64_t offset_ns;
    };

    // Construct from glob patterns with per-pattern time offsets
    explicit pcap_iterator(std::vector<std::pair<std::string, std::int64_t>> specs) {
        for (auto& [pattern, offset] : specs) {
            expand_glob(pattern, offset);
        }
        init_queue();
    }

    // Construct from pre-built sources (used by zip handler)
    explicit pcap_iterator(std::vector<source_entry> entries)
        : sources_(std::move(entries)) {
        init_queue();
    }

    pcap_iterator(const pcap_iterator&) = delete;
    pcap_iterator& operator=(const pcap_iterator&) = delete;
    pcap_iterator(pcap_iterator&&) = default;
    pcap_iterator& operator=(pcap_iterator&&) = default;

    bool advance() override {
        if (done_) return false;

        // Lazy advance: push the previous current source back into the queue
        if (has_current_) {
            auto& entry = sources_[current_];
            if (entry.source->advance()) {
                queue_.push({adjusted_time(current_), current_});
            }
        }

        if (queue_.empty()) {
            done_ = true;
            return false;
        }

        auto top = queue_.top();
        queue_.pop();
        current_ = top.source_index;
        has_current_ = true;

        return true;
    }

    // Adjusted timestamp (raw + offset)
    std::uint64_t timestamp_ns() const override {
        auto raw = sources_[current_].source->timestamp_ns();
        return static_cast<std::uint64_t>(
            static_cast<std::int64_t>(raw) + sources_[current_].offset_ns);
    }

    // Original timestamp from pcap (before offset adjustment)
    std::uint64_t raw_time() const {
        return sources_[current_].source->timestamp_ns();
    }

    const std::byte* data() const override {
        return sources_[current_].source->data();
    }

    std::uint32_t length() const override {
        return sources_[current_].source->length();
    }

    bool done() const override { return done_; }

    std::size_t source_count() const { return sources_.size(); }

private:
    struct queue_entry {
        std::uint64_t adjusted_time;
        std::size_t source_index;
        bool operator>(const queue_entry& other) const {
            return adjusted_time > other.adjusted_time;
        }
    };

    std::vector<source_entry> sources_;
    std::priority_queue<queue_entry, std::vector<queue_entry>, std::greater<queue_entry>> queue_;
    std::size_t current_ = 0;
    bool has_current_ = false;
    bool done_ = false;

    std::uint64_t adjusted_time(std::size_t idx) const {
        auto raw = sources_[idx].source->timestamp_ns();
        return static_cast<std::uint64_t>(
            static_cast<std::int64_t>(raw) + sources_[idx].offset_ns);
    }

    void init_queue() {
        for (std::size_t i = 0; i < sources_.size(); i++) {
            if (sources_[i].source->advance()) {
                queue_.push({adjusted_time(i), i});
            }
        }
        done_ = queue_.empty();
    }

    void expand_glob(const std::string& pattern, std::int64_t offset) {
        glob_t g{};
        int ret = ::glob(pattern.c_str(), GLOB_TILDE | GLOB_NOCHECK, nullptr, &g);
        if (ret != 0 && ret != GLOB_NOMATCH) {
            globfree(&g);
            throw std::runtime_error("glob failed for: " + pattern);
        }

        for (std::size_t i = 0; i < g.gl_pathc; i++) {
            std::string path = g.gl_pathv[i];
            add_source(path, offset);
        }
        globfree(&g);
    }

    void add_source(const std::string& path, std::int64_t offset) {
        if (has_zip_extension(path)) {
#ifdef HAS_LIBZIP
            auto zip_sources = open_zip_pcaps(path);
            for (auto& src : zip_sources) {
                sources_.push_back({std::move(src), offset});
            }
#else
            throw std::runtime_error("zip file detected but HAS_LIBZIP not compiled: " + path);
#endif
        } else {
            sources_.push_back({std::make_unique<pcap_file>(path), offset});
        }
    }

    static bool has_zip_extension(const std::string& path) {
        if (path.size() < 4) return false;
        auto ext = path.substr(path.size() - 4);
        return ext == ".zip" || ext == ".ZIP";
    }
};

} // namespace packet
#include "PcapFile.hpp"
#include "frame.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <zlib.h>

namespace {

struct PacketView {
    const unsigned char* data;
    std::size_t size;
};

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void append_u32_le(std::vector<std::byte>& out, std::uint32_t value) {
    out.push_back(static_cast<std::byte>(value & 0xffu));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    out.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    out.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
}

void append_bytes(std::vector<std::byte>& out, const unsigned char* data, std::size_t size) {
    auto first = reinterpret_cast<const std::byte*>(data);
    out.insert(out.end(), first, first + size);
}

std::vector<std::byte> make_classic_pcap(const std::vector<PacketView>& packets) {
    std::vector<std::byte> bytes;
    std::size_t total_size = 24;
    for (const auto& packet : packets) {
        total_size += 16 + packet.size;
    }
    bytes.reserve(total_size);

    append_u32_le(bytes, 0xa1b2c3d4u);
    bytes.push_back(std::byte{0x02});
    bytes.push_back(std::byte{0x00});
    bytes.push_back(std::byte{0x04});
    bytes.push_back(std::byte{0x00});
    append_u32_le(bytes, 0u);
    append_u32_le(bytes, 0u);
    append_u32_le(bytes, 65535u);
    append_u32_le(bytes, 1u);

    for (std::size_t i = 0; i < packets.size(); ++i) {
        const auto& packet = packets[i];
        append_u32_le(bytes, static_cast<std::uint32_t>(100 + i));
        append_u32_le(bytes, static_cast<std::uint32_t>((i * 1000) % 1000000));
        append_u32_le(bytes, static_cast<std::uint32_t>(packet.size));
        append_u32_le(bytes, static_cast<std::uint32_t>(packet.size));
        append_bytes(bytes, packet.data, packet.size);
    }

    return bytes;
}

class TempFile {
public:
    TempFile(const std::filesystem::path& path, const std::vector<std::byte>& bytes)
        : path_(path) {
        std::ofstream out(path_, std::ios::binary);
        if (!out) {
            throw std::runtime_error("failed to create temp file: " + path_.string());
        }
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!out) {
            throw std::runtime_error("failed to write temp file: " + path_.string());
        }
    }

    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    const std::filesystem::path& path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

class TempGzipFile {
public:
    TempGzipFile(const std::filesystem::path& path, const std::vector<std::byte>& bytes)
        : path_(path) {
        gzFile file = gzopen(path_.string().c_str(), "wb");
        if (!file) {
            throw std::runtime_error("failed to create gzip file: " + path_.string());
        }

        auto written = gzwrite(file,
                               reinterpret_cast<const void*>(bytes.data()),
                               static_cast<unsigned int>(bytes.size()));
        auto close_result = gzclose(file);

        if (written == 0 || close_result != Z_OK) {
            throw std::runtime_error("failed to write gzip file: " + path_.string());
        }
    }

    ~TempGzipFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    const std::filesystem::path& path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

std::uint64_t count_packets(const std::filesystem::path& path) {
    packet::PcapFile pcap(path.string());
    std::uint64_t count = 0;

    while (pcap.advance()) {
        ++count;
    }

    return count;
}

void test_raw_and_gzip_packet_counts_match() {
    unsigned char udp_bytes[] = {
        0x01, 0x00, 0x5e, 0x00, 0x1f, 0x01, 0x00, 0x1c, 0x73, 0x15, 0x3c, 0x4c,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x20, 0x59, 0x73, 0x40, 0x00, 0x3a, 0x11,
        0x39, 0x90, 0xcd, 0xd1, 0xdf, 0x46, 0xe0, 0x00, 0x1f, 0x01, 0x37, 0xe6,
        0x37, 0xe6, 0x00, 0x0c, 0x8e, 0x18, 0xde, 0xad, 0xbe, 0xef
    };
    unsigned char tcp_bytes[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x81, 0x00, 0x00, 0x64, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x12, 0x34,
        0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0a, 0xc0, 0xa8,
        0x01, 0x14, 0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    std::vector<PacketView> packets;
    packets.reserve(512);
    for (int i = 0; i < 256; ++i) {
        packets.push_back({udp_bytes, sizeof(udp_bytes)});
        packets.push_back({tcp_bytes, sizeof(tcp_bytes)});
    }

    auto raw_bytes = make_classic_pcap(packets);
    auto temp_dir = std::filesystem::temp_directory_path();
    TempFile raw_file(temp_dir / "hpcap_roundtrip_test.pcap", raw_bytes);
    TempGzipFile gzip_file(temp_dir / "hpcap_roundtrip_test.pcap.gz", raw_bytes);

    const auto raw_count = count_packets(raw_file.path());
    const auto gzip_count = count_packets(gzip_file.path());

    expect(raw_count == packets.size(), "unexpected raw packet count");
    expect(gzip_count == packets.size(), "unexpected gzip packet count");
    expect(raw_count == gzip_count, "raw and gzip packet counts should match");
}

} // namespace

int main() {
    try {
        test_raw_and_gzip_packet_counts_match();
        std::cout << "pcap_roundtrip_tests passed" << std::endl;
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "pcap_roundtrip_tests failed: " << ex.what() << std::endl;
        return 1;
    }
}

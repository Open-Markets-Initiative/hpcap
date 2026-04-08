#include "Parser.hpp"
#include "PcapFile.hpp"
#include "frame.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace {

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

std::vector<std::byte> make_classic_pcap(const unsigned char* udp,
                                         std::size_t udp_size,
                                         const unsigned char* tcp,
                                         std::size_t tcp_size) {
    std::vector<std::byte> bytes;
    bytes.reserve(24 + 16 + udp_size + 16 + tcp_size);

    append_u32_le(bytes, 0xa1b2c3d4u);
    bytes.push_back(std::byte{0x02});
    bytes.push_back(std::byte{0x00});
    bytes.push_back(std::byte{0x04});
    bytes.push_back(std::byte{0x00});
    append_u32_le(bytes, 0u);
    append_u32_le(bytes, 0u);
    append_u32_le(bytes, 65535u);
    append_u32_le(bytes, 1u);

    append_u32_le(bytes, 1u);
    append_u32_le(bytes, 250u);
    append_u32_le(bytes, static_cast<std::uint32_t>(udp_size));
    append_u32_le(bytes, static_cast<std::uint32_t>(udp_size));
    append_bytes(bytes, udp, udp_size);

    append_u32_le(bytes, 2u);
    append_u32_le(bytes, 500u);
    append_u32_le(bytes, static_cast<std::uint32_t>(tcp_size));
    append_u32_le(bytes, static_cast<std::uint32_t>(tcp_size));
    append_bytes(bytes, tcp, tcp_size);

    return bytes;
}

class TempFile {
public:
    explicit TempFile(std::vector<std::byte> bytes)
        : path_(std::filesystem::temp_directory_path() / "hpcap_test_capture.pcap") {
        std::ofstream out(path_, std::ios::binary);
        if (!out) {
            throw std::runtime_error("failed to create temp pcap file");
        }
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!out) {
            throw std::runtime_error("failed to write temp pcap file");
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

TEST(PcapTest, ReadsPacketsFromClassicPcap) {
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

    TempFile file(make_classic_pcap(udp_bytes, sizeof(udp_bytes), tcp_bytes, sizeof(tcp_bytes)));
    packet::PcapFile pcap(file.path().string());

    ASSERT_TRUE(pcap.advance());
    EXPECT_EQ(pcap.timestamp_ns(), 1000250000ULL);
    EXPECT_EQ(pcap.length(), 46u);

    packet::Frame first(pcap.data(), pcap.length());
    EXPECT_TRUE(first.valid());
    EXPECT_TRUE(first.is_udp());
    EXPECT_EQ(first.dst_port, 14310u);

    ASSERT_TRUE(pcap.advance());
    EXPECT_EQ(pcap.timestamp_ns(), 2000500000ULL);
    EXPECT_EQ(pcap.length(), 58u);

    packet::Frame second(pcap.data(), pcap.length());
    EXPECT_TRUE(second.valid());
    EXPECT_TRUE(second.is_tcp());
    EXPECT_EQ(second.vlan_id, 100u);

    EXPECT_FALSE(pcap.advance());
    EXPECT_TRUE(pcap.done());
}

TEST(PcapTest, ParserTracksCurrentFrame) {
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

    TempFile file(make_classic_pcap(udp_bytes, sizeof(udp_bytes), tcp_bytes, sizeof(tcp_bytes)));
    packet::Parser parser(file.path().string());

    ASSERT_TRUE(parser.next());
    EXPECT_TRUE(parser.frame().valid());
    EXPECT_TRUE(parser.frame().is_udp());

    ASSERT_TRUE(parser.next());
    EXPECT_TRUE(parser.frame().valid());
    EXPECT_TRUE(parser.frame().is_tcp());
    EXPECT_EQ(parser.frame().vlan_id, 100u);

    EXPECT_FALSE(parser.next());
    EXPECT_FALSE(parser.frame().valid());
}

} // namespace

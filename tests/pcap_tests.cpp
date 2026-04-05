#include "Parser.hpp"
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

namespace {

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

void test_pcap_file_reads_packets() {
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

    expect(pcap.advance(), "expected first packet");
    expect(pcap.timestamp_ns() == 1000250000ULL, "unexpected first packet timestamp");
    expect(pcap.length() == 46u, "unexpected first packet length");

    packet::Frame first(pcap.data(), pcap.length());
    expect(first.valid(), "expected first packet frame to be valid");
    expect(first.is_udp(), "expected first packet to be UDP");
    expect(first.dst_port == 14310u, "unexpected first packet destination port");

    expect(pcap.advance(), "expected second packet");
    expect(pcap.timestamp_ns() == 2000500000ULL, "unexpected second packet timestamp");
    expect(pcap.length() == 58u, "unexpected second packet length");

    packet::Frame second(pcap.data(), pcap.length());
    expect(second.valid(), "expected second packet frame to be valid");
    expect(second.is_tcp(), "expected second packet to be TCP");
    expect(second.vlan_id == 100u, "unexpected second packet VLAN id");

    expect(!pcap.advance(), "expected end of file after two packets");
    expect(pcap.done(), "expected pcap reader to be done");
}

void test_parser_tracks_current_frame() {
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

    expect(parser.next(), "expected parser to yield first frame");
    expect(parser.frame().valid(), "expected parser current frame to be valid");
    expect(parser.frame().is_udp(), "expected parser first frame to be UDP");

    expect(parser.next(), "expected parser to yield second frame");
    expect(parser.frame().valid(), "expected parser second frame to be valid");
    expect(parser.frame().is_tcp(), "expected parser second frame to be TCP");
    expect(parser.frame().vlan_id == 100u, "unexpected parser second frame VLAN id");

    expect(!parser.next(), "expected parser end of file");
    expect(!parser.frame().valid(), "expected parser cached frame to reset after EOF");
}

} // namespace

int main() {
    try {
        test_pcap_file_reads_packets();
        test_parser_tracks_current_frame();
        std::cout << "pcap_tests passed" << std::endl;
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "pcap_tests failed: " << ex.what() << std::endl;
        return 1;
    }
}

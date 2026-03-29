#include "Parser.hpp"
#include "PcapFile.hpp"
#include "frame.hpp"

#include <array>
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

std::array<std::byte, 46> make_udp_frame() {
    return {
        std::byte{0x01}, std::byte{0x00}, std::byte{0x5e}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x1c}, std::byte{0x73}, std::byte{0x15}, std::byte{0x3c}, std::byte{0x4c},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x20},
        std::byte{0x59}, std::byte{0x73}, std::byte{0x40}, std::byte{0x00},
        std::byte{0x3a}, std::byte{0x11}, std::byte{0x39}, std::byte{0x90},
        std::byte{0xcd}, std::byte{0xd1}, std::byte{0xdf}, std::byte{0x46},
        std::byte{0xe0}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x01},
        std::byte{0x37}, std::byte{0xe6}, std::byte{0x37}, std::byte{0xe6},
        std::byte{0x00}, std::byte{0x0c}, std::byte{0x8e}, std::byte{0x18},
        std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}
    };
}

std::array<std::byte, 58> make_vlan_tcp_frame() {
    return {
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
        std::byte{0x81}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x64},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28},
        std::byte{0x12}, std::byte{0x34}, std::byte{0x40}, std::byte{0x00},
        std::byte{0x40}, std::byte{0x06}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x0a},
        std::byte{0xc0}, std::byte{0xa8}, std::byte{0x01}, std::byte{0x14},
        std::byte{0x30}, std::byte{0x39}, std::byte{0x00}, std::byte{0x50},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x50}, std::byte{0x02}, std::byte{0x20}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
    };
}

void append_u32_le(std::vector<std::byte>& out, std::uint32_t value) {
    out.push_back(static_cast<std::byte>(value & 0xffu));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
    out.push_back(static_cast<std::byte>((value >> 16) & 0xffu));
    out.push_back(static_cast<std::byte>((value >> 24) & 0xffu));
}

void append_bytes(std::vector<std::byte>& out, const std::byte* data, std::size_t size) {
    out.insert(out.end(), data, data + size);
}

std::vector<std::byte> make_classic_pcap() {
    auto udp = make_udp_frame();
    auto tcp = make_vlan_tcp_frame();

    std::vector<std::byte> bytes;
    bytes.reserve(24 + 16 + udp.size() + 16 + tcp.size());

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
    append_u32_le(bytes, static_cast<std::uint32_t>(udp.size()));
    append_u32_le(bytes, static_cast<std::uint32_t>(udp.size()));
    append_bytes(bytes, udp.data(), udp.size());

    append_u32_le(bytes, 2u);
    append_u32_le(bytes, 500u);
    append_u32_le(bytes, static_cast<std::uint32_t>(tcp.size()));
    append_u32_le(bytes, static_cast<std::uint32_t>(tcp.size()));
    append_bytes(bytes, tcp.data(), tcp.size());

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
    TempFile file(make_classic_pcap());
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
    TempFile file(make_classic_pcap());
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

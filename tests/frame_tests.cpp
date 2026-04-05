#include "frame.hpp"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_udp_frame() {
    unsigned char bytes[] = {
        0x01, 0x00, 0x5e, 0x00, 0x1f, 0x01, 0x00, 0x1c, 0x73, 0x15, 0x3c, 0x4c,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x59, 0x73, 0x40, 0x00, 0x3a, 0x11,
        0x39, 0x90, 0xcd, 0xd1, 0xdf, 0x46, 0xe0, 0x00, 0x1f, 0x01, 0x37, 0xe6,
        0x37, 0xe6, 0x00, 0x0c, 0x8e, 0x18, 0xde, 0xad, 0xbe, 0xef
    };

    packet::Frame frame(reinterpret_cast<const std::byte*>(bytes),
                        static_cast<std::uint32_t>(sizeof(bytes)));

    expect(frame.valid(), "expected UDP frame to be valid");
    expect(frame.is_udp(), "expected UDP protocol");
    expect(!frame.is_tcp(), "did not expect TCP protocol");
    expect(frame.src_port == 14310, "unexpected UDP source port");
    expect(frame.dst_port == 14310, "unexpected UDP destination port");
    expect(frame.payload_len == 4, "unexpected UDP payload length");
    expect(frame.vlan_id == 0, "did not expect VLAN tag");

    auto src = packet::Frame::octets(frame.src_ip);
    auto dst = packet::Frame::octets(frame.dst_ip);
    expect(src.a == 205 && src.b == 209 && src.c == 223 && src.d == 70, "unexpected source IP");
    expect(dst.a == 224 && dst.b == 0 && dst.c == 31 && dst.d == 1, "unexpected destination IP");
}

void test_vlan_tcp_frame() {
    unsigned char bytes[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x81, 0x00, 0x00, 0x64, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x12, 0x34,
        0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x0a, 0xc0, 0xa8,
        0x01, 0x14, 0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    packet::Frame frame(reinterpret_cast<const std::byte*>(bytes),
                        static_cast<std::uint32_t>(sizeof(bytes)));

    expect(frame.valid(), "expected TCP frame to be valid");
    expect(frame.is_tcp(), "expected TCP protocol");
    expect(!frame.is_udp(), "did not expect UDP protocol");
    expect(frame.vlan_id == 100, "unexpected VLAN id");
    expect(frame.src_port == 12345, "unexpected TCP source port");
    expect(frame.dst_port == 80, "unexpected TCP destination port");
    expect(frame.payload_len == 0, "unexpected TCP payload length");
}

void test_truncated_frame() {
    unsigned char bytes[] = { 0x00 };

    packet::Frame frame(reinterpret_cast<const std::byte*>(bytes), 0);

    expect(!frame.valid(), "expected truncated frame to be invalid");
}

void test_non_ipv4_frame() {
    unsigned char bytes[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x06
    };

    packet::Frame frame(reinterpret_cast<const std::byte*>(bytes),
                        static_cast<std::uint32_t>(sizeof(bytes)));

    expect(!frame.valid(), "expected non-IPv4 ethernet frame to be invalid");
}

void test_truncated_udp_header() {
    unsigned char bytes[] = {
        0x01, 0x00, 0x5e, 0x00, 0x1f, 0x01, 0x00, 0x1c, 0x73, 0x15, 0x3c, 0x4c,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x20, 0x59, 0x73, 0x40, 0x00, 0x3a, 0x11,
        0x39, 0x90, 0xcd, 0xd1, 0xdf, 0x46, 0xe0, 0x00, 0x1f, 0x01, 0x37, 0xe6,
        0x37, 0xe6
    };

    packet::Frame frame(reinterpret_cast<const std::byte*>(bytes),
                        static_cast<std::uint32_t>(sizeof(bytes)));

    expect(!frame.valid(), "expected truncated UDP frame to be invalid");
}

void test_non_udp_tcp_ipv4_frame() {
    unsigned char bytes[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01,
        0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x08, 0x00,
        0xf7, 0xff, 0x00, 0x01, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
        0xba, 0xbe
    };

    packet::Frame frame(reinterpret_cast<const std::byte*>(bytes),
                        static_cast<std::uint32_t>(sizeof(bytes)));

    expect(!frame.valid(), "expected non-UDP/TCP IPv4 frame to remain invalid");
    expect(frame.ip_protocol == 1, "expected ICMP protocol to still be decoded");
}

} // namespace

int main() {
    try {
        test_udp_frame();
        test_vlan_tcp_frame();
        test_truncated_frame();
        test_non_ipv4_frame();
        test_truncated_udp_header();
        test_non_udp_tcp_ipv4_frame();
        std::cout << "frame_tests passed" << std::endl;
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "frame_tests failed: " << ex.what() << std::endl;
        return 1;
    }
}

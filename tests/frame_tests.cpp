#include "frame.hpp"

#include <array>
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

std::array<std::byte, 46> make_udp_frame() {
    return {
        std::byte{0x01}, std::byte{0x00}, std::byte{0x5e}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x1c}, std::byte{0x73}, std::byte{0x15}, std::byte{0x3c}, std::byte{0x4c},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28},
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

std::array<std::byte, 14> make_arp_frame() {
    return {
        std::byte{0xff}, std::byte{0xff}, std::byte{0xff}, std::byte{0xff}, std::byte{0xff}, std::byte{0xff},
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x08}, std::byte{0x06}
    };
}

std::array<std::byte, 38> make_truncated_udp_frame() {
    return {
        std::byte{0x01}, std::byte{0x00}, std::byte{0x5e}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x1c}, std::byte{0x73}, std::byte{0x15}, std::byte{0x3c}, std::byte{0x4c},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x20},
        std::byte{0x59}, std::byte{0x73}, std::byte{0x40}, std::byte{0x00},
        std::byte{0x3a}, std::byte{0x11}, std::byte{0x39}, std::byte{0x90},
        std::byte{0xcd}, std::byte{0xd1}, std::byte{0xdf}, std::byte{0x46},
        std::byte{0xe0}, std::byte{0x00}, std::byte{0x1f}, std::byte{0x01},
        std::byte{0x37}, std::byte{0xe6}, std::byte{0x37}, std::byte{0xe6}
    };
}

std::array<std::byte, 54> make_non_udp_tcp_ipv4_frame() {
    return {
        std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
        std::byte{0x66}, std::byte{0x77}, std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x40}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x0a}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        std::byte{0x08}, std::byte{0x00}, std::byte{0xf7}, std::byte{0xff},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01},
        std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef},
        std::byte{0xca}, std::byte{0xfe}, std::byte{0xba}, std::byte{0xbe}
    };
}

void test_udp_frame() {
    auto bytes = make_udp_frame();
    packet::Frame frame(bytes.data(), static_cast<std::uint32_t>(bytes.size()));

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
    auto bytes = make_vlan_tcp_frame();
    packet::Frame frame(bytes.data(), static_cast<std::uint32_t>(bytes.size()));

    expect(frame.valid(), "expected TCP frame to be valid");
    expect(frame.is_tcp(), "expected TCP protocol");
    expect(!frame.is_udp(), "did not expect UDP protocol");
    expect(frame.vlan_id == 100, "unexpected VLAN id");
    expect(frame.src_port == 12345, "unexpected TCP source port");
    expect(frame.dst_port == 80, "unexpected TCP destination port");
    expect(frame.payload_len == 0, "unexpected TCP payload length");
}

void test_truncated_frame() {
    std::array<std::byte, 10> bytes{};
    packet::Frame frame(bytes.data(), static_cast<std::uint32_t>(bytes.size()));

    expect(!frame.valid(), "expected truncated frame to be invalid");
}

void test_non_ipv4_frame() {
    auto bytes = make_arp_frame();
    packet::Frame frame(bytes.data(), static_cast<std::uint32_t>(bytes.size()));

    expect(!frame.valid(), "expected non-IPv4 ethernet frame to be invalid");
}

void test_truncated_udp_header() {
    auto bytes = make_truncated_udp_frame();
    packet::Frame frame(bytes.data(), static_cast<std::uint32_t>(bytes.size()));

    expect(!frame.valid(), "expected truncated UDP frame to be invalid");
}

void test_non_udp_tcp_ipv4_frame() {
    auto bytes = make_non_udp_tcp_ipv4_frame();
    packet::Frame frame(bytes.data(), static_cast<std::uint32_t>(bytes.size()));

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

#include "../include/PcapFile.hpp"
#include "../include/frame.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

static void fmt_ts(std::uint64_t ts) {
    auto secs = ts / 1000000000ULL;
    auto frac = ts % 1000000000ULL;
    std::cout << secs << "." << std::setfill('0') << std::setw(9)
              << frac << std::setfill(' ');
}

static void fmt_ip(std::uint32_t ip_net) {
    auto o = packet::Frame::octets(ip_net);
    std::cout << static_cast<unsigned>(o.a) << "."
              << static_cast<unsigned>(o.b) << "."
              << static_cast<unsigned>(o.c) << "."
              << static_cast<unsigned>(o.d);
}

static void test_file(const std::string& label,
                      const std::string& path,
                      std::uint64_t max_packets = 0) {
    std::cout << "=== " << label << " ===" << std::endl;
    std::cout << "Path: " << path << std::endl;

    auto t0 = std::chrono::steady_clock::now();
    packet::PcapFile pcap(path);

    std::uint64_t count = 0;
    std::uint64_t first_ts = 0;
    std::uint64_t last_ts = 0;
    std::uint64_t prev_ts = 0;
    std::uint32_t min_len = UINT32_MAX;
    std::uint32_t max_len = 0;
    bool monotonic = true;

    std::uint64_t udp_count = 0;
    std::uint64_t tcp_count = 0;
    std::uint64_t invalid_count = 0;
    std::uint64_t vlan_count = 0;
    std::map<std::uint16_t, std::uint64_t> dst_port_dist;
    std::uint32_t min_payload = UINT32_MAX;
    std::uint32_t max_payload = 0;
    std::uint64_t total_payload = 0;

    while (pcap.advance()) {
        count++;
        auto ts = pcap.timestamp_ns();
        auto len = pcap.length();
        packet::Frame f(pcap.data(), len);

        if (count == 1) {
            first_ts = ts;
        }
        if (ts < prev_ts) {
            monotonic = false;
        }
        prev_ts = ts;
        last_ts = ts;

        min_len = std::min(min_len, len);
        max_len = std::max(max_len, len);

        if (!f.valid()) {
            invalid_count++;
        } else if (f.is_udp()) {
            udp_count++;
        } else if (f.is_tcp()) {
            tcp_count++;
        }

        if (f.vlan_id != 0) {
            vlan_count++;
        }

        if (f.valid()) {
            dst_port_dist[f.dst_port]++;
            min_payload = std::min(min_payload, f.payload_len);
            max_payload = std::max(max_payload, f.payload_len);
            total_payload += f.payload_len;
        }

        if (count <= 5) {
            std::cout << "  pkt " << std::setw(3) << count << ": ts=";
            fmt_ts(ts);
            std::cout << "  len=" << std::setw(5) << len;

            if (f.valid()) {
                std::cout << "  " << (f.is_udp() ? "UDP" : f.is_tcp() ? "TCP" : "IP")
                          << " ";
                fmt_ip(f.src_ip);
                std::cout << ":" << f.src_port << " -> ";
                fmt_ip(f.dst_ip);
                std::cout << ":" << f.dst_port
                          << "  payload=" << f.payload_len;
                if (f.vlan_id != 0) {
                    std::cout << "  vlan=" << f.vlan_id;
                }
            } else {
                std::cout << "  (not IPv4 UDP/TCP)";
            }
            std::cout << std::endl;
        }

        if (max_packets > 0 && count >= max_packets) {
            break;
        }
    }

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    std::cout << "Packets: " << count;
    if (max_packets > 0 && count >= max_packets) {
        std::cout << " (stopped at limit)";
    }
    std::cout << std::endl;

    if (count > 0) {
        std::cout << "First ts: ";
        fmt_ts(first_ts);
        std::cout << std::endl;

        std::cout << "Last ts:  ";
        fmt_ts(last_ts);
        std::cout << std::endl;

        std::cout << "Packet len: min=" << min_len << " max=" << max_len << std::endl;
        std::cout << "Monotonic: " << (monotonic ? "yes" : "NO") << std::endl;
        std::cout << "--- Frame dissection ---" << std::endl;
        std::cout << "UDP: " << udp_count
                  << "  TCP: " << tcp_count
                  << "  Non-IPv4/other: " << invalid_count
                  << std::endl;
        if (vlan_count > 0) {
            std::cout << "VLAN-tagged: " << vlan_count << std::endl;
        }

        auto valid_total = udp_count + tcp_count;
        if (valid_total > 0) {
            std::cout << "Payload len: min=" << min_payload
                      << " max=" << max_payload
                      << " avg=" << (total_payload / valid_total) << std::endl;
        }

        std::vector<std::pair<std::uint64_t, std::uint16_t>> port_vec;
        for (const auto& [port, cnt] : dst_port_dist) {
            port_vec.push_back({cnt, port});
        }
        std::sort(port_vec.rbegin(), port_vec.rend());
        std::cout << "Top dst ports:";
        for (std::size_t i = 0; i < 5 && i < port_vec.size(); i++) {
            std::cout << " " << port_vec[i].second << "(" << port_vec[i].first << ")";
        }
        std::cout << std::endl;
    }

    std::cout << "Time: " << ms << " ms" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap-path> [more-paths...]" << std::endl;
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        test_file(argv[i], argv[i], 10000);
    }

    return 0;
}

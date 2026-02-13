#include "../packet/pcap_iterator.hpp"
#include "../packet/frame.hpp"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>

static void fmt_ts(std::uint64_t ts) {
    auto secs = ts / 1000000000ULL;
    auto frac = ts % 1000000000ULL;
    std::cout << secs << "." << std::setfill('0') << std::setw(9)
              << frac << std::setfill(' ');
}

static void fmt_ip(std::uint32_t ip_net) {
    auto o = packet::frame::octets(ip_net);
    std::cout << static_cast<unsigned>(o.a) << "."
              << static_cast<unsigned>(o.b) << "."
              << static_cast<unsigned>(o.c) << "."
              << static_cast<unsigned>(o.d);
}

static void test_source(const std::string& label,
                        const std::string& pattern,
                        std::int64_t offset = 0,
                        std::uint64_t max_packets = 0) {
    std::cout << "=== " << label << " ==" << "=" << std::endl;
    std::cout << "Pattern: " << pattern << std::endl;

    auto t0 = std::chrono::steady_clock::now();

    packet::pcap_iterator iter({{pattern, offset}});

    std::uint64_t count = 0;
    std::uint64_t first_ts = 0, last_ts = 0;
    std::uint32_t min_len = UINT32_MAX, max_len = 0;
    bool monotonic = true;
    std::uint64_t prev_ts = 0;

    // Frame dissection stats
    std::uint64_t udp_count = 0, tcp_count = 0, other_count = 0, invalid_count = 0;
    std::uint64_t vlan_count = 0;
    std::map<std::uint16_t, std::uint64_t> dst_port_dist;
    std::uint32_t min_payload = UINT32_MAX, max_payload = 0;
    std::uint64_t total_payload = 0;

    while (iter.advance()) {
        count++;
        auto ts = iter.timestamp_ns();
        auto len = iter.length();

        if (count == 1) first_ts = ts;
        if (ts < prev_ts) monotonic = false;
        prev_ts = ts;
        last_ts = ts;

        if (len < min_len) min_len = len;
        if (len > max_len) max_len = len;

        // Dissect frame
        packet::frame f(iter.data(), iter.length());

        if (!f.valid()) {
            invalid_count++;
        } else if (f.is_udp()) {
            udp_count++;
        } else if (f.is_tcp()) {
            tcp_count++;
        } else {
            other_count++;
        }

        if (f.vlan_id != 0) vlan_count++;

        if (f.valid()) {
            dst_port_dist[f.dst_port]++;
            if (f.payload_len < min_payload) min_payload = f.payload_len;
            if (f.payload_len > max_payload) max_payload = f.payload_len;
            total_payload += f.payload_len;
        }

        if (count <= 5) {
            auto secs = ts / 1000000000ULL;
            auto frac = ts % 1000000000ULL;
            std::cout << "  pkt " << std::setw(3) << count
                      << ": ts=" << secs << "."
                      << std::setfill('0') << std::setw(9) << frac
                      << std::setfill(' ')
                      << "  len=" << std::setw(5) << len;

            if (f.valid()) {
                std::cout << "  " << (f.is_udp() ? "UDP" : f.is_tcp() ? "TCP" : "???")
                          << " ";
                fmt_ip(f.src_ip);
                std::cout << ":" << f.src_port << " -> ";
                fmt_ip(f.dst_ip);
                std::cout << ":" << f.dst_port
                          << "  payload=" << f.payload_len;
                if (f.vlan_id != 0)
                    std::cout << "  vlan=" << f.vlan_id;
            } else {
                std::cout << "  (not IPv4 UDP/TCP)";
            }
            std::cout << std::endl;
        }

        if (max_packets > 0 && count >= max_packets) break;
    }

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    std::cout << "Packets: " << count;
    if (max_packets > 0 && count >= max_packets)
        std::cout << " (stopped at limit)";
    std::cout << std::endl;

    if (count > 0) {
        std::cout << "First ts: "; fmt_ts(first_ts); std::cout << std::endl;
        std::cout << "Last ts:  "; fmt_ts(last_ts);  std::cout << std::endl;
        std::cout << "Packet len: min=" << min_len << " max=" << max_len << std::endl;
        std::cout << "Monotonic: " << (monotonic ? "yes" : "NO — timestamps out of order") << std::endl;

        // Frame dissection summary
        std::cout << "--- Frame dissection ---" << std::endl;
        std::cout << "UDP: " << udp_count << "  TCP: " << tcp_count
                  << "  Other IP: " << other_count
                  << "  Non-IPv4: " << invalid_count << std::endl;
        if (vlan_count > 0)
            std::cout << "VLAN-tagged: " << vlan_count << std::endl;

        auto valid_total = udp_count + tcp_count + other_count;
        if (valid_total > 0) {
            std::cout << "Payload len: min=" << min_payload
                      << " max=" << max_payload
                      << " avg=" << (total_payload / valid_total) << std::endl;
        }

        // Top 5 destination ports
        std::vector<std::pair<std::uint64_t, std::uint16_t>> port_vec;
        for (auto& [port, cnt] : dst_port_dist)
            port_vec.push_back({cnt, port});
        std::sort(port_vec.rbegin(), port_vec.rend());
        std::cout << "Top dst ports:";
        for (std::size_t i = 0; i < 5 && i < port_vec.size(); i++)
            std::cout << " " << port_vec[i].second << "(" << port_vec[i].first << ")";
        std::cout << std::endl;
    }
    std::cout << "Time: " << ms << " ms" << std::endl;
    std::cout << "Sources: " << iter.source_count() << std::endl;
    std::cout << std::endl;
}

int main() {
    // Test 1: gzip pcap — first 10k packets from IEX DEEP
    test_source("IEX DEEP (gzip, first 10k packets)",
                "/data/pcaps/data_feeds_20260211_20260211_IEXTP1_DEEP1.0.pcap.gz",
                0, 10000);

    // Test 2: zip with zstd-compressed pcap entries
    test_source("CME GLOBEX zip (pcap.zst entries, first 10k packets)",
                "/data/pcaps/dc3-glbx-a-20230716.zip",
                0, 10000);

    // Test 3: gzip pcap — IEX TOPS first 10k
    test_source("IEX TOPS (gzip, first 10k packets)",
                "/data/pcaps/data_feeds_20260211_20260211_IEXTP1_TOPS1.6.pcap.gz",
                0, 10000);

    // Test 4: multi-source merge — both IEX feeds interleaved
    std::cout << "=== Multi-source merge (DEEP + TOPS, first 10k) ==" << "=" << std::endl;
    {
        auto t0 = std::chrono::steady_clock::now();
        packet::pcap_iterator iter({
            {"/data/pcaps/data_feeds_20260211_20260211_IEXTP1_DEEP1.0.pcap.gz", 0},
            {"/data/pcaps/data_feeds_20260211_20260211_IEXTP1_TOPS1.6.pcap.gz", 0}
        });

        std::uint64_t count = 0;
        bool monotonic = true;
        std::uint64_t prev_ts = 0;
        std::uint64_t first_ts = 0, last_ts = 0;

        while (iter.advance() && count < 10000) {
            count++;
            auto ts = iter.timestamp_ns();
            if (count == 1) first_ts = ts;
            if (ts < prev_ts) monotonic = false;
            prev_ts = ts;
            last_ts = ts;
        }

        auto t1 = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

        std::cout << "Packets: " << count << std::endl;
        std::cout << "First ts: "; fmt_ts(first_ts); std::cout << std::endl;
        std::cout << "Last ts:  "; fmt_ts(last_ts);  std::cout << std::endl;
        std::cout << "Monotonic: " << (monotonic ? "yes" : "NO") << std::endl;
        std::cout << "Sources: " << iter.source_count() << std::endl;
        std::cout << "Time: " << ms << " ms" << std::endl;
    }

    return 0;
}
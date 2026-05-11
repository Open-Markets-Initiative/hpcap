#pragma once

#include "PcapFile.hpp"
#include "Frame.hpp"

#include <string>
namespace packet {

    // pcap parser
    struct Parser {

        packet::PcapFile pcap;
        packet::Frame current_frame;

        explicit Parser(const std::string& path)
          : pcap{ path } {}

        // Advance to the next packet and refresh the cached frame view.
        bool next() {
            if (!pcap.advance()) {
                current_frame = packet::Frame{};
                return false;
            }
            current_frame = packet::Frame{ pcap.data(), pcap.length() };
            return true;
        }

        // Get the frame view for the most recent successful next().
        const Frame& frame() const {
            return current_frame;
        }
    };
}

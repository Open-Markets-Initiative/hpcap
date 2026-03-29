#pragma once

#include "PcapFile.hpp"
#include "frame.hpp"

#include <string>
namespace packet {

    // pcap parser
    struct Parser {

        packet::PcapFile pcap;
        packet::Frame current_frame;

        explicit Parser(const std::string& path)
          : pcap{ path } {}

        // load next pcap frame
        bool next() {
            return pcap.advance();
        }

        // parse the current frame into the cached view
        void identify() {
            current_frame = packet::Frame{ pcap.data(), pcap.length() };
        }

        // get current frame
        const Frame& frame() const {
            return current_frame;
        }
    };
}

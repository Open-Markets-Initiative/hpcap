#pragma once

#include "PcapFile.hpp"
#include "Frame.hpp"
#include "Settings.hpp"
#include "Result.hpp"

namespace packet {

    // pcap parser
    struct Parser {

        packet::PcapFile pcap;
        packet::Frame current_frame;

        const packet::Options& options;

        explicit Parser(const packet::Options& options)
          : options{ options }, pcap{ options.file } {}

        // load next pcap frame
        bool next() {
            return pcap.advance();
        }

        // parse frame and identify protocol
        result identify() {
            current_frame = packet::Frame{ pcap.data(), pcap.length() };

            if (current_frame.is_udp()) {
                return result::nasdaq_nsmequities_totalview_itch_v5_0;
            }

            return result::unknown;
        }

        // get current frame
        const Frame& frame() const {
            return current_frame;
        }
    };
}
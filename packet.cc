// Copyright 2008, Stephane Jacob <stephane.jacob@m4x.org>
// Copyright 2008, John Whitbeck <john.whitbeck@m4x.org>
// Copyright 2008, Vincent Zanotti <vincent.zanotti@m4x.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "base/logging.h"
#include "packet.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

Packet::Packet(const char* packet, uint32 packet_length)
  : l3_protocol_(0),
    l3_ipv4_src_(0), l3_ipv4_dst_(0),
    l3_ipv6_src_(), l3_ipv6_dst_(),
    l4_protocol_(0), l4_src_(0), l4_dst_(0),
    payload_size_(0), payload_location_(NULL) {
  int result = parse(packet, packet_length);
  if (result == -2) {
    l4_protocol_ = 0;
  } else if (result < 0) {
    l3_protocol_ = 0;
  }
}

int Packet::parse(const char* packet, uint32 packet_length) {
  // Determines the l3 protocol, the l3 addresses, and the start-of-l4.
  if (packet_length < 1) {
    LOG(INFO, "Parsed invalid empty packet.");
    return -1;
  }

  uint32 l4_header_start;
  l3_protocol_ = (packet[0] >> 4);
  if (l3_protocol_ == 4) {
    // Checks for the minimal header length.
    if (packet_length < sizeof(struct iphdr)) {
      LOG(INFO, "Parsed invalid ipv4 packet (too short).");
      return -1;
    }

    // Checks for total packet length vs. header packet length.
    const iphdr* ip4_header = reinterpret_cast<const iphdr*>(packet);
    if (ntohs(ip4_header->tot_len) != packet_length) {
      LOG(INFO, "Parsed invalid ipv4 packet (invalid length).");
      return -1;
    }

    // Extracts informations from the IP4 header.
    l3_ipv4_src_ = ip4_header->saddr;
    l3_ipv4_dst_ = ip4_header->daddr;
    l4_header_start = 4 * ip4_header->ihl;
    l4_protocol_ = ip4_header->protocol;
  } else if (l3_protocol_ == 6) {
    // Checks for the minimal header length.
    if (packet_length < sizeof(struct ip6_hdr)) {
      LOG(INFO, "Parsed invalid ipv6 packet (too short).");
      return -1;
    }

    // Checks for total packet length vs. header packet length.
    const ip6_hdr* ip6_header = reinterpret_cast<const ip6_hdr*>(packet);
    if ((ntohs(ip6_header->ip6_plen) + sizeof(struct ip6_hdr)) != packet_length) {
      LOG(INFO, "Parsed invalid ipv6 packet (invalid length).");
      return -1;
    }

    // Extracts informations from the IP6 header.
    l3_ipv6_src_ = ip6_header->ip6_src;
    l3_ipv6_dst_ = ip6_header->ip6_dst;
    l4_header_start = sizeof(struct ip6_hdr);
    l4_protocol_ = ip6_header->ip6_nxt;
  } else {
    return 0;
  }

  // Prepares the l4-specific fields, and sets up the payload start.
  if (l4_protocol_ == IPPROTO_TCP) {
    // Checks for the minimal header length.
    if (packet_length < l4_header_start + sizeof(struct tcphdr)) {
      LOG(INFO, "Parsed invalid TCP packet (too short).");
      return -2;
    }

    // Parses the tcp header.
    const tcphdr* tcp_header =
        reinterpret_cast<const tcphdr*>(packet + l4_header_start);
    int l4_header_length = 4 * tcp_header->doff;

    l4_src_ = ntohs(tcp_header->source);
    l4_dst_ = ntohs(tcp_header->dest);
    payload_size_ = packet_length - l4_header_start - l4_header_length;
    payload_location_ = packet + l4_header_start + l4_header_length;
  } else if (l4_protocol_ == IPPROTO_UDP) {
    // Checks for the minimal header length.
    if (packet_length < l4_header_start + sizeof(struct udphdr)) {
      LOG(INFO, "Parsed invalid UDP packet (too short).");
      return -2;
    }

    // Checks for total packet length vs. header packet length.
    const udphdr* udp_header =
        reinterpret_cast<const udphdr*>(packet+l4_header_start);
    if (l4_header_start + ntohs(udp_header->len) != packet_length) {
      LOG(INFO, "Parsed invalid UDP packet (invalid length).");
      return -2;
    }

    l4_src_ = ntohs(udp_header->source);
    l4_dst_ = ntohs(udp_header->dest);
    payload_size_ = packet_length - l4_header_start - sizeof(struct udphdr);
    payload_location_ = packet + l4_header_start + sizeof(struct udphdr);
  }
  return 0;
}

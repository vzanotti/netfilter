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

#ifndef PACKET_H__
#define PACKET_H__

#include "base/basictypes.h"
#include <netinet/in.h>

// Parses a raw network packet, and extracts useful information (l3 protocol,
// l4 protocol, size and location of the final payload).
class Packet {
 public:
  // Initializes the Packet with the @p packet.
  Packet(const char* packet, uint32 packet_length);

  // Layer-3 protocol accessors (ipv4 addresses are in network order).
  uint8 l3_protocol() const { return l3_protocol_; }
  uint32 l3_ipv4_src() const { return l3_ipv4_src_; }
  uint32 l3_ipv4_dst() const { return l3_ipv4_dst_; }
  const in6_addr* l3_ipv6_src() const { return &l3_ipv6_src_; }
  const in6_addr* l3_ipv6_dst() const { return &l3_ipv6_dst_; }

  // Layer-4 protocol accessors.
  uint8 l4_protocol() const { return l4_protocol_; }
  uint16 l4_src() const { return l4_src_; }
  uint16 l4_dst() const { return l4_dst_; }

  // Payload accessors.
  int32 payload_size() const { return payload_size_; }
  const char* payload() const { return payload_location_; }

 private:
  int parse(const char* packet, uint32 packet_length);

  // Layer-3 protocol ressources.
  uint8 l3_protocol_;
  uint32 l3_ipv4_src_;
  uint32 l3_ipv4_dst_;
  in6_addr l3_ipv6_src_;
  in6_addr l3_ipv6_dst_;

  // Layer-4 protocol ressources.
  uint8 l4_protocol_;
  uint16 l4_src_;
  uint16 l4_dst_;

  // Payload ressources.
  int32 payload_size_;
  const char* payload_location_;

  DISALLOW_EVIL_CONSTRUCTORS(Packet);
};

#endif  // PACKET_H__

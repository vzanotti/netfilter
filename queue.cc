// Copyright 2008, Stephane Jacob <stephane.jacob@m4x.org>
// Copyright 2008, John Whitbeck <john.whitbeck@m4x.org>
// Copyright 2008, Vincent Zanotti <vincent.zanotti@m4x.org>
//
// Based on l7-queue.cpp from l7-filter-userspace 0.4
// Based on nfqnl_test.c from libnetfilter-queue 0.0.12
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
#include "queue.h"
#include <linux/netfilter.h>

Queue::Queue(int queue, uint32 mark_mask, ConnTrack* conntrack)
  : conntrack_(conntrack), queue_(queue),
    queue_handle_(NULL), queue_socket_(NULL) {
  if (!set_mark_mask(mark_mask)) {
    LOG(FATAL, "The mark mask must only have consecutive bits on. "
               "Eg. 0x0ff0 is correct, while 0xf0f0 is not.");
  }

  // Creates a new queue_handle.
  queue_handle_ = nfq_open();
  if (!queue_handle_) {
    LOG(FATAL, "Unable to open the netfilter queue (%s)", strerror(errno));
  }

  // Unbinds existing queue handlers on domains AF_INET and AF_INET6.
  // No check is performed on return value since kernel <= 2.6.24 always
  // return -1.
  LOG(INFO, "Unbinding existing nf_queue handlers for AF_INET/AF_INET6.");
  nfq_unbind_pf(queue_handle_, AF_INET);
  nfq_unbind_pf(queue_handle_, AF_INET6);

  // Binds our queue handler to AF_INET and AF_INET6 domains.
  LOG(INFO, "Binding our handler as nf_queue handler for AF_INET/AF_INET6.");
  if (nfq_bind_pf(queue_handle_, AF_INET) < 0) {
    LOG(FATAL, "Could not bind our handler as AF_INET nf_queue handler (%s).",
        strerror(errno));
  }
  if (nfq_bind_pf(queue_handle_, AF_INET6) < 0) {
    LOG(FATAL, "Could not bind our handler as AF_INET6 nf_queue handler (%s).",
        strerror(errno));
  }
}

Queue::~Queue() {
  if (queue_socket_ != NULL) {
    nfq_destroy_queue(queue_socket_);
    queue_socket_ = NULL;
  }

  if (queue_handle_ != NULL) {
    nfq_unbind_pf(queue_handle_, AF_INET);
    nfq_unbind_pf(queue_handle_, AF_INET6);
    nfq_close(queue_handle_);
    queue_handle_ = NULL;
  }
}

void Queue::Run() {
  // Creates a queue handler for our NFQUEUE, sets up a callback on it, and
  // activates the copy_packet mode (so we can peek at the packet's content).
  LOG(INFO, "Creates a queue handler for NFQUEUE %d.", queue_);
  queue_socket_ = nfq_create_queue(queue_handle_,
                                   queue_,
                                   Queue::queue_callback,
                                   static_cast<void*>(this));
  if (!queue_socket_) {
    LOG(FATAL, "Could not bind to NFQUEUE %d (%s).", queue_, strerror(errno));
  }
  if (nfq_set_mode(queue_socket_, NFQNL_COPY_PACKET, 0xffff) < 0) {
    LOG(FATAL, "Could not set copy_packet mode for NFQUEUE %d (%s).",
        queue_, strerror(errno));
  }

  // Listens to the queue, and processes packets.
  int fd = nfnl_fd(nfq_nfnlh(queue_handle_));

  int received;
  char buffer[kBufferSize];
  for (; (received = recv(fd, buffer, kBufferSize, 0)) && received >= 0;) {
    nfq_handle_packet(queue_handle_, buffer, received);
  }

  // Unbinds from our NFQUEUE.
  nfq_destroy_queue(queue_socket_);
  queue_socket_ = NULL;
}

int Queue::queue_callback(nfq_q_handle* queue_handle,
                          nfgenmsg* nf_msg,
                          nfq_data* nf_data,
                          void* queue_object) {
  // If available, redirects the packet to the Queue's handler.
  Queue* queue = reinterpret_cast<Queue*>(queue_object);
  if (queue) {
    return queue->handle_packet(queue_handle, nf_msg, nf_data);
  }

  // Computes the packet's id, and accepts it.
  nfqnl_msg_packet_hdr* packet_header = nfq_get_msg_packet_hdr(nf_data);
  if (packet_header) {
    return nfq_set_verdict(
        queue_handle,
        ntohl(packet_header->packet_id),  // Packet id.
        NF_ACCEPT,                        // Verdict.
        0, NULL);                         // Optionnal mangled packet.
  }
  return nfq_set_verdict(queue_handle, 0, NF_ACCEPT, 0, NULL);
}

int Queue::handle_packet(nfq_q_handle* queue_handle,
                         nfgenmsg* nf_msg,
                         nfq_data* nf_data) {
  // Parses important information from the nf packet.
  uint32 packet_id = 0;
  nfqnl_msg_packet_hdr* packet_header = nfq_get_msg_packet_hdr(nf_data);
  if (packet_header) {
    packet_id = ntohl(packet_header->packet_id);
  }

  uint32 packet_mark = nfq_get_nfmark(nf_data);
  pair<uint32, uint32> packet_submarks = get_submarks_from_mark(packet_mark);

  // Fetches the raw packet, and stops processing packets we don't want to
  // handle (at this time, we're only able to process ipv4/ipv6 tcp/udp).
  char* packet_data;
  int packet_length = nfq_get_payload(nf_data, &packet_data);
  if (packet_length < 0) {
    return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, NULL);
  }

  Packet packet(packet_data, packet_length);
  if ((packet.l3_protocol() != 4 &&
       packet.l3_protocol() != 6) ||
      (packet.l4_protocol() != IPPROTO_TCP &&
       packet.l4_protocol() != IPPROTO_UDP)) {
    return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, NULL);
  }

  // Drops packets without any payload; these packets are usually TCP control
  // packets (SYN, SYN ACK, RST, ...), which will only confuse the conntrack
  // matcher).
  if (packet.payload_size() <= 0) {
    return nfq_set_verdict(queue_handle, packet_id, NF_ACCEPT, 0, NULL);
  }

  // Determines the conntrack keys for the packet, and fetches the corresponding
  // Connection object from the conntrack table.
  pair<string, string> conntrack_keys = conntrack_->get_packet_keys(packet);
  bool direction_orig = true;
  Connection* connection =
      conntrack_->get_connection_or_create(conntrack_keys, direction_orig);

  CHECK(connection != NULL);
  if (direction_orig) {
    connection->update_packet_orig(packet.payload(), packet.payload_size());
  } else {
    connection->update_packet_repl(packet.payload(), packet.payload_size());
  }

  // Classifies the packet.
  uint32 local_mark = connection->classification_mark();
  connection->Release();

  uint32 final_mark = get_final_mark(packet_submarks.first, local_mark);
  return nfq_set_verdict_mark(queue_handle, packet_id, NF_ACCEPT,
                              htonl(final_mark), 0, NULL);
}

bool Queue::set_mark_mask(uint32 mark_mask) {
  int low_bit = -1, high_bit = -1;
  int mask = mark_mask;

  for (int position = 0; mask > 0; ++position, mask >>= 1) {
    if (mask & 0x1) {
      high_bit = position;
      if (low_bit < 0) {
        low_bit = position;
      }
    }
  }

  mark_mask_ = ((1 << (high_bit - low_bit + 1)) - 1) << low_bit;
  mark_mask_first_bit_ = low_bit;
  return mark_mask_ == mark_mask;
}

pair<uint32, uint32> Queue::get_submarks_from_mark(uint32 mark) {
  return pair<int32, int32>(
      mark & ~mark_mask_,
      (mark & mark_mask_) >> mark_mask_first_bit_);
}

uint32 Queue::get_final_mark(uint32 previous_mark, uint32 local_mark) {
  return (previous_mark & ~mark_mask_) |
         ((local_mark << mark_mask_first_bit_) & mark_mask_);

}

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

#ifndef QUEUE_H__
#define QUEUE_H__

#include "conntrack.h"
extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
}

// NFQUEUE processing class.
// The Queue object opens a socket on the appropriate NFQUEUE, listens for
// packets, transmits them to the classifier, and returns them with the
// classification verdict mark.
class Queue {
 public:
  // Size of the input buffer; should be large enough to handle any packet.
  static const int kBufferSize = 4096;

  // Sets up the queue, and binds it to the appropriate queue.
  // The @p markmask indicates which part of the NF mark as to be overwritten
  // with our classification-determined result.
  Queue(int queue, uint32 mark_mask, ConnTrack* conntrack);
  ~Queue();

  // Starts the queue listener; only returns on failure.
  void Run();
  void Stop();

  // Static callback for the queue packet listerner.
  // Calls the handle_packet of the @p queue_object, or accepts the packet
  // if queue_object is NULL.
  static int queue_callback(nfq_q_handle* queue_handle,
                            nfgenmsg* nf_msg,
                            nfq_data* nf_data,
                            void* queue_object);

 private:
  // Processes the packet, updates the conntrack/classifier, and sets the
  // final mark.
  int handle_packet(nfq_q_handle* queue_handle,
                    nfgenmsg* nf_msg,
                    nfq_data* nf_data);

  // Netfilter mark helpers.
  bool set_mark_mask(uint32 mark_mask);
  pair<uint32, uint32> get_submarks_from_mark(uint32 mark);
  uint32 get_final_mark(uint32 previous_mark, uint32 local_mark);

  // Pointer to the connection tracker -- used to get Connection objects.
  ConnTrack* conntrack_;

  // No. of the NFQUEUE to listen to.
  int queue_;

  // Mark bitmask.
  uint32 mark_mask_first_bit_;
  uint32 mark_mask_;

  // Queue listener handler.
  nfq_handle* queue_handle_;
  nfq_q_handle* queue_socket_;
  bool must_stop_;

  DISALLOW_EVIL_CONSTRUCTORS(Queue);
};

#endif  // QUEUE_H__

// Copyright 2008, Stephane Jacob <stephane.jacob@m4x.org>
// Copyright 2008, John Whitbeck <john.whitbeck@m4x.org>
// Copyright 2008, Vincent Zanotti <vincent.zanotti@m4x.org>
//
// Based on l7-conntrack.cpp from l7-filter-userspace 0.4
// Based on source code from libnetfilter-conntrack svn-r7519
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

#ifndef CONNTRACK_H__
#define CONNTRACK_H__

#include "base/atomicops.h"
#include "base/basictypes.h"
#include "base/hash_map.h"
#include "base/mutex.h"
#include "packet.h"
#include <ext/hash_map>
#include <netinet/in.h>
extern "C" {
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
}

using std::pair;
using std::string;
using std::hash_map;

class Classifier;
class ConnectionClassifier;

// TODO: add comments
// Provided the Acquire/Release methods are used correctly, the object is
// thread-safe.
class Connection {
 public:
  // Limits above which the classifier is destroyed, and the connection is
  // classified as "unmatched".
  static const uint32 kMaxBufferSize = 16 * (1 << 10);  // 16k

  explicit Connection(bool conntracked, Classifier* classifier);
  ~Connection();

  // "Is conntracked ?" accessors/mutators.
  bool conntracked() const { return conntracked_; }
  void set_conntracked(bool conntracked) { conntracked_ = conntracked; }

  // Classification mark accessor.
  uint32 classification_mark() const { return classification_mark_; }

  // Exchanged content accessors.
  inline int32 packets_egress() const { return packets_egress_; }
  inline int32 packets_ingress() const { return packets_ingress_; }
  inline int32 bytes_egress() const { return bytes_egress_; }
  inline int32 bytes_ingress() const { return bytes_ingress_; }
  inline const string& buffer_egress() const { return buffer_egress_; }
  inline const string& buffer_ingress() const { return buffer_ingress_; }

  // Updates the connection with the @p content of the packet.
  // "original" means src->dst, "repl" means dst->src.
  void update_packet_orig(const char* data, int32 data_len);
  void update_packet_repl(const char* data, int32 data_len);

  // Reverses the ConnectionClassifier object, for when conntrack started using
  // the wrong ORIG & REPL directions.
  void reverse_connection();

  // Thread-safety: each instance must Acquire() the object before using it
  // (which prevents other from using it). Release() must be called when not
  // used anymore.
  void Acquire() {
    AtomicIncrement(&ref_counter_, 1);
    content_lock_.Lock();
  }
  void Release() {
    AtomicIncrement(&ref_counter_, -1);
    content_lock_.Unlock();
    if (ref_counter_ == 0) {
      delete this;
    }
  }
  void Destroy() {
    content_lock_.Lock();
    Release();
  }

 private:
  // Really updates the Connection (Cf. update_packet_* above).
  void update_packet(bool orig, const char* data, int32 data_len);

  // Tears down the classifier and the buffers (called on definitive
  // classification).
  void set_definitive_classification();

  // Indicates if the connection have already be seen by ConnTrack.
  bool conntracked_;

  // The classification object.
  ConnectionClassifier* classifier_;

  // Stores the current rule match. This number is an opaque number from the
  // classifier, and is supposed to be the NFQUEUE verdict mark.
  int32 classification_mark_;
  bool definitive_mark_;

  // Content received so far; packets_* and bytes_* stores real numbers.
  // Buffers only store the last received bytes: it actually stores bytes
  // from the [bytes_*gress - buffer_*gress.size();bytes_*gress[.
  uint32 packets_egress_;
  uint32 packets_ingress_;
  uint32 bytes_egress_;
  uint32 bytes_ingress_;
  string buffer_egress_;
  string buffer_ingress_;

  // Thread-safety.
  AtomicWord ref_counter_;
  Mutex content_lock_;

  DISALLOW_EVIL_CONSTRUCTORS(Connection);
};

// TODO: add comments
// Format of conntrack keys:
//   Conntrack elements are identified by a string, named key, which uniquely
//   identifies the conntrack item, and which is easily derived from a matched
//   packet. It is formated the following way:
//    "<proto> src=<src> dst=<dst> sport=<sport> dport=<dport>"
class ConnTrack {
 public:
  // Static data used to compute the key.
  static const char* kProtoNames[IPPROTO_MAX];

  // Sets up the conntrack event listener, and register the @p classifier for
  // future connections.
  ConnTrack(Classifier* classifier);
  ~ConnTrack();

  // Starts the conntrack event listener; only returns on failure.
  void Run();
  void Stop();

  // Returns true iff the given conntrack key is associated with an existing
  // connection.
  bool has_connection(const string& key);

  // Returns the connection identified by the @p key, and increment its usage
  // counter, or returns NULL on failure.
  Connection* get_connection(const string& key);

  // Returns the connection identified by any of the two @p keys, and updates
  // the @p direction_orig to indicates which key was used.
  // If no connection is found, returns a new connection for the original
  // direction.
  Connection* get_connection_or_create(const pair<string, string>& keys,
                                       bool& direction_orig);

  // Returns the pair of tracking keys associated with the @p packet.
  // The input @p packet is the complete queue structure (the packet, plus
  // netfilter-queue headers).
  // The first key will be the "forward direction key" (for when the @p packet
  // is a src->dst packet), the second will be the "backward direction packet".
  static pair<string, string> get_packet_keys(const Packet& packet);

  // Static callback for the conntrack event listener.
  // Calls the handle_conntrack_event of the @p conntrack_object, or returns
  // NFCT_CB_FAILURE on failure.
  static int conntrack_callback(nf_conntrack_msg_type type,
                                nf_conntrack* conntrack_event,
                                void* conntrack_object);

 private:
  // Processes the conntrack events, and updates the connections table.
  int handle_conntrack_event(nf_conntrack_msg_type type,
                             nf_conntrack* conntrack_event);

  // Returns the connection identified by the @p key. Assumes that the caller
  // owns a lock on connections_lock_.
  inline Connection* get_connection_locked(const string& key) {
    hash_map<string, Connection*>::iterator it = connections_.find(key);
    if (it != connections_.end()) {
      it->second->Acquire();
      return it->second;
    }
    return NULL;
  }

  // Returns the conntrack key associated to the @p conntrack event.
  // If @p orig_dir is true, returns the original direction key, otherwise
  // returns the reverse direction key.
  static string get_conntrack_key(const nf_conntrack* conntrack_event,
                                  bool orig_dir);

  // Conntrack events listener.
  nfct_handle* conntrack_event_handler_;

  // Pointer to the connection classifier.
  Classifier* classifier_;

  // Connection storage, and mutex.
  hash_map<string, Connection*> connections_;
  Mutex connections_lock_;
  bool must_stop_;

  DISALLOW_EVIL_CONSTRUCTORS(ConnTrack);
};

#endif  // CONNTRACK_H__

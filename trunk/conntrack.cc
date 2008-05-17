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

#include "base/googleinit.h"
#include "base/logging.h"
#include "base/util.h"
#include "classifier.h"
#include "conntrack.h"
#include "packet.h"
#include <set>
#include <arpa/inet.h>
#include <sys/time.h>

using std::set;

//
// Connection tracking key creation helpers.
//
static const char* kProtoNames[IPPROTO_MAX];

// Initializes the protocol-to-name conversion table.
void kProtoNames_initializer() {
  for (int i = 0; i < IPPROTO_MAX; ++i) {
    kProtoNames[i] = NULL;
  }

  kProtoNames[IPPROTO_TCP] = "tcp";
  kProtoNames[IPPROTO_UDP] = "udp";
}
REGISTER_MODULE_INITIALIZER(kProtoNames, kProtoNames_initializer());

// Returns a string made from the @p protocol number. This function is NOT
// re-entrant.
static char protocol_buffer__[64];
const char* sprintf_protocol(uint8 proto) {
  if (kProtoNames[proto] == NULL) {
    snprintf(protocol_buffer__, sizeof(protocol_buffer__), "l4-unk-%d", proto);
    return protocol_buffer__;
  }
  return kProtoNames[proto];
}

// Returns a string made from the @p ipv4/ipv6 address.
string sprintf_ipv4_address(uint32 address) {
  in_addr ipv4_address;
  ipv4_address.s_addr = address;

  return inet_ntoa(ipv4_address);
}

string sprintf_ipv6_address(const void* address) {
  in6_addr ipv6_address;
  memcpy(&ipv6_address, address, sizeof(struct in6_addr));

  char tmp[INET6_ADDRSTRLEN];
  if (!inet_ntop(AF_INET6, &ipv6_address, tmp, sizeof(tmp))) {
    return "(null)";
  }

  return tmp;
}

//
// Walltime helper.
//
static double WallTime() {
  struct timeval result;
  gettimeofday(&result, NULL);

  return double(result.tv_sec) + double(result.tv_usec) / 1000000.0;
}

//
// Implementation of the Connection class.
//
Connection::Connection(bool conntracked, Classifier* classifier)
  : conntracked_(conntracked),
    classification_mark_(Classifier::kNoMatchYet),
    packets_egress_(0), packets_ingress_(0),
    bytes_egress_(0), bytes_ingress_(0),
    buffer_egress_(), buffer_ingress_(),
    last_packet_(-1),
    ref_counter_(1), content_lock_() {
  Acquire();
  if (classifier) {
    classifier_ = classifier->get_connection_classifier(this);
  } else {
    classifier_ = NULL;
    classification_mark_ = Classifier::kNoMatch;
    definitive_mark_ = true;
  }
}

Connection::~Connection() {
  if (classifier_) {
    delete classifier_;
    classifier_ = NULL;
  }
}

void Connection::touch() {
  last_packet_ = WallTime();
}

void Connection::update_packet_orig(const char* data, int32 data_len) {
  update_packet(true, data, data_len);
}

void Connection::update_packet_repl(const char* data, int32 data_len) {
  update_packet(false, data, data_len);
}

void Connection::update_packet(bool orig, const char* data, int32 data_len) {
  CHECK(data_len >= 0);

  // If classification is definitive, stops the packet processing.
  if (definitive_mark_) {
    return;
  }

  // Appends data to the ingress/egress buffers.
  if (orig) {
    packets_egress_++;
    bytes_egress_ += data_len;
    buffer_egress_.append(data, data_len);
  } else {
    packets_ingress_++;
    bytes_ingress_ += data_len;
    buffer_ingress_.append(data, data_len);
  }

  // Calls the classifier for status update; it returns the status of the
  // classification. If it is definitive, tears down the classifier.
  bool classified = classifier_->update();
  classification_mark_ = classifier_->classification_mark();
  if (classified) {
    set_definitive_classification();
    return;
  }

  // Asks the classifier for buffer hints, and shrinks the buffer where needed.
  uint32 hint_egress = classifier_->egress_hint();
  uint32 hint_ingress = classifier_->ingress_hint();

  if (hint_egress > (bytes_egress_ - buffer_egress_.size())) {
    CHECK(hint_egress <= bytes_egress_);
    int32 new_buffer_size = bytes_egress_ - hint_egress;
    int32 new_buffer_start = buffer_egress_.size() - new_buffer_size;

    string new_buffer(buffer_egress_.data() + new_buffer_start,
                      new_buffer_size);
    buffer_egress_.swap(new_buffer);
  }
  if (hint_ingress > (bytes_ingress_ - buffer_ingress_.size())) {
    CHECK(hint_ingress <= bytes_ingress_);
    int32 new_buffer_size = bytes_ingress_ - hint_ingress;
    int32 new_buffer_start = buffer_ingress_.size() - new_buffer_size;

    string new_buffer(buffer_ingress_.data() + new_buffer_start,
                      new_buffer_size);
    buffer_ingress_.swap(new_buffer);
  }

  // If buffers grow above a threshold, kill the classification.
  if (buffer_ingress_.size() > kMaxBufferSize ||
      buffer_egress_.size() > kMaxBufferSize) {
    classification_mark_ = Classifier::kNoMatch;
    set_definitive_classification();
  }
}

void Connection::set_definitive_classification() {
  if (classifier_) {
    delete classifier_;
    classifier_ = NULL;
  }

  buffer_ingress_.clear();
  buffer_egress_.clear();
  definitive_mark_ = true;
}

void Connection::reverse_connection() {
  if (classifier_) {
    classifier_->reverse_connection();
  }

  std::swap(packets_egress_, packets_ingress_);
  std::swap(bytes_egress_, bytes_ingress_);
  std::swap(buffer_egress_, buffer_ingress_);
}

//
// Implementation of the ConnTrack class.
//
ConnTrack::ConnTrack(Classifier* classifier)
    : classifier_(classifier),
      connections_(),
      connections_lock_(),
      must_stop_(false),
      last_gc_(-1) {
  // Sets up the conntrack events listener.
  conntrack_event_handler_ = nfct_open(
      CONNTRACK,
      NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY);
  if (!conntrack_event_handler_) {
    LOG(FATAL, "Unable to set up the conntrack event listener. "
               "Either you don't have root privileges, or there is no "
               "kernel support for conntract/nfnetlink/nf_netlink_ct.");
  }
}

ConnTrack::~ConnTrack() {
  if (conntrack_event_handler_) {
    nfct_close(conntrack_event_handler_);
    conntrack_event_handler_ = NULL;
  }

  WriterMutexLock ml(&connections_lock_);
  for (hash_map<string, Connection*>::iterator it = connections_.begin();
       it != connections_.end(); ++it)  {
    if (it->second != NULL) {
      it->second->Destroy();
    }
  }
  connections_.clear();
}

void ConnTrack::Run() {
  int result = nfct_callback_register(
      conntrack_event_handler_,
      static_cast<nf_conntrack_msg_type>(NFCT_T_NEW | NFCT_T_DESTROY),
      ConnTrack::conntrack_callback,
      static_cast<void*>(this));
  if (result < 0) {
    LOG(FATAL, "Unable to set up the conntrack event callback (%d - %s).",
        result, strerror(errno));
  }

  result = nfct_catch(conntrack_event_handler_);
  if (result < 0) {
    LOG(FATAL, "Unable to set up the conntrack event listener (%d - %s).",
        result, strerror(errno));
  }

  if (conntrack_event_handler_) {
    nfct_close(conntrack_event_handler_);
    conntrack_event_handler_ = NULL;
  }
}

void ConnTrack::Stop() {
  must_stop_ = true;
}

bool ConnTrack::has_connection(const string& key) {
  ReaderMutexLock ml(&connections_lock_);
  return connections_.find(key) != connections_.end();
}

Connection* ConnTrack::get_connection(const string& key) {
  ReaderMutexLock ml(&connections_lock_);
  return get_connection_locked(key);
}

Connection* ConnTrack::get_connection_or_create(
    const pair<string, string>& keys, bool& direction_orig) {
  WriterMutexLock ml(&connections_lock_);

  Connection* connection = get_connection_locked(keys.first);
  direction_orig = true;
  if (!connection) {
    connection = get_connection_locked(keys.second);
    direction_orig = false;

    if (!connection) {
      LOG(INFO, "Got un-conntracked packet '%s'.", keys.first.c_str());
      connections_[keys.first] = new Connection(false, classifier_);
      connection = connections_[keys.first];
      direction_orig = true;
    }
  }

  return connection;
}

void ConnTrack::get_packet_keys(const Packet& packet,
                                pair<string, string>* keys) {
  string l3_conntrack_orig, l3_conntrack_repl;

  if (packet.l3_protocol() == 4) {
    SStringPrintf(
        &l3_conntrack_orig,
        "src=%s dst=%s",
        sprintf_ipv4_address(packet.l3_ipv4_src()).c_str(),
        sprintf_ipv4_address(packet.l3_ipv4_dst()).c_str());
    SStringPrintf(
        &l3_conntrack_repl,
        "src=%s dst=%s",
        sprintf_ipv4_address(packet.l3_ipv4_dst()).c_str(),
        sprintf_ipv4_address(packet.l3_ipv4_src()).c_str());
  } else if (packet.l3_protocol() == 6) {
    SStringPrintf(
        &l3_conntrack_orig,
        "src=%s dst=%s",
        sprintf_ipv6_address(packet.l3_ipv6_src()).c_str(),
        sprintf_ipv6_address(packet.l3_ipv6_dst()).c_str());
    SStringPrintf(
        &l3_conntrack_repl,
        "src=%s dst=%s",
        sprintf_ipv6_address(packet.l3_ipv6_dst()).c_str(),
        sprintf_ipv6_address(packet.l3_ipv6_src()).c_str());
  } else {
     SStringPrintf(&l3_conntrack_orig, "l3-unk-%d", packet.l3_protocol());
     SStringPrintf(&l3_conntrack_repl, "l3-unk-%d", packet.l3_protocol());
  }

  SStringPrintf(&keys->first,
                "%s %s sport=%d dport=%d",
                sprintf_protocol(packet.l4_protocol()),
                l3_conntrack_orig.c_str(),
                packet.l4_src(), packet.l4_dst());
  SStringPrintf(&keys->second,
                "%s %s sport=%d dport=%d",
                sprintf_protocol(packet.l4_protocol()),
                l3_conntrack_repl.c_str(),
                packet.l4_dst(), packet.l4_src());
}

int ConnTrack::conntrack_callback(nf_conntrack_msg_type type,
                                  nf_conntrack* conntrack_event,
                                  void* conntrack_object) {
  ConnTrack* conntrack = reinterpret_cast<ConnTrack*>(conntrack_object);
  if (conntrack) {
    if (conntrack->must_stop_) {
      return NFCT_CB_STOP;
    }
    return conntrack->handle_conntrack_event(type, conntrack_event);
  }

  LOG(ERROR, "No conntracker in conntrack_callback; aborting event listener.");
  return NFCT_CB_FAILURE;
}

int ConnTrack::handle_conntrack_event(nf_conntrack_msg_type type,
                                      nf_conntrack* conntrack_event) {
  // Discards unknown events, error events, and NULL events.
  if (type == NFCT_T_UNKNOWN || type == NFCT_T_ERROR) {
    return NFCT_CB_CONTINUE;
  }
  if (conntrack_event == NULL) {
    LOG(INFO, "Got real event (type %d) with NULL conntrack.", type);
    return NFCT_CB_CONTINUE;
  }

  // Discards conntrack event for l4 proto other than tcp & udp.
  uint8 l4_proto = nfct_get_attr_u8(conntrack_event, ATTR_L4PROTO);
  if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP) {
    return NFCT_CB_CONTINUE;
  }

  // Garbage collects the old conntrack, when required.
  if (WallTime() > last_gc_ + kGCInterval) {
    WriterMutexLock ml(&connections_lock_);
    last_gc_ = WallTime();

    double expiration_time = last_gc_ - kOldConntrackLifetime;
    set<string> gckeys;
    for (hash_map<string, Connection*>::iterator it = connections_.begin();
         it != connections_.end(); ++it) {
      if (it->second != NULL) {
        if (it->second->last_packet() > 0 &&
            it->second->last_packet() < expiration_time) {
          gckeys.insert(it->first);
        }
      }
    }

    LOG(INFO, "Conntrack garbage collection: removed %d items.", gckeys.size());
    for (set<string>::iterator it = gckeys.begin(); it != gckeys.end(); ++it) {
      connections_.erase(*it);
    }
  }

  // Creates a new connection on new conntrack item.
  if (type == NFCT_T_NEW) {
    string key = get_conntrack_key(conntrack_event, true);

    WriterMutexLock ml(&connections_lock_);
    hash_map<string, Connection*>::iterator connection = connections_.find(key);
    if (connection != connections_.end()) {
      if (connection->second != NULL) {
        connection->second->set_conntracked(true);
      } else {
        connection->second = new Connection(true, classifier_);
        connection->second->Release();
      }
    } else {
      string reverse_key = get_conntrack_key(conntrack_event, false);
      hash_map<string, Connection*>::iterator reverse_connection =
          connections_.find(key);

      // Looks for an existing "reverse" connection -- happens when a packet is
      // first seen on the Queue before the conntracker becomes aware of the
      // underlying connection.
      if (reverse_connection != connections_.end()) {
        LOG(INFO, "Reverse connection found for orig key '%s'.", key.c_str());
        reverse_connection->second->Acquire();
        reverse_connection->second->reverse_connection();
        reverse_connection->second->Release();
        connections_[key] = reverse_connection->second;
        connections_.erase(reverse_key);
      } else {
        connections_[key] = new Connection(true, classifier_);
        connections_[key]->Release();
      }
    }
  }

  // Deletes older connections.
  if (type == NFCT_T_DESTROY) {
    string key = get_conntrack_key(conntrack_event, true);

    WriterMutexLock ml(&connections_lock_);
    hash_map<string, Connection*>::iterator connection = connections_.find(key);
    if (connection != connections_.end()) {
      if (connection->second != NULL) {
        connection->second->Destroy();
      }
      connections_.erase(connection);
    }
  }

  return NFCT_CB_CONTINUE;
}

string ConnTrack::get_conntrack_key(const nf_conntrack* conntrack_event,
                                    bool orig_dir) {
  uint8 l3_proto = nfct_get_attr_u8(conntrack_event, ATTR_L3PROTO);
  uint8 l4_proto = nfct_get_attr_u8(conntrack_event, ATTR_L4PROTO);
  uint16 src_port = ntohs(nfct_get_attr_u16(conntrack_event, ATTR_PORT_SRC));
  uint16 dst_port = ntohs(nfct_get_attr_u16(conntrack_event, ATTR_PORT_DST));

  if (l3_proto == AF_INET) {
    uint32 src_address = nfct_get_attr_u32(conntrack_event, ATTR_IPV4_SRC);
    uint32 dst_address = nfct_get_attr_u32(conntrack_event, ATTR_IPV4_DST);

    return StringPrintf(
        "%s src=%s dst=%s sport=%d dport=%d",
        sprintf_protocol(l4_proto),
        sprintf_ipv4_address(orig_dir ? src_address : dst_address).c_str(),
        sprintf_ipv4_address(orig_dir ? dst_address : src_address).c_str(),
        orig_dir ? src_port : dst_port,
        orig_dir ? dst_port : src_port);
  } else if (l3_proto == AF_INET6) {
    const void* src_address = nfct_get_attr(conntrack_event, ATTR_IPV6_SRC);
    const void* dst_address = nfct_get_attr(conntrack_event, ATTR_IPV6_DST);

    return StringPrintf(
        "%s src=%s dst=%s sport=%d dport=%d",
        sprintf_protocol(l4_proto),
        sprintf_ipv6_address(orig_dir ? src_address : dst_address).c_str(),
        sprintf_ipv6_address(orig_dir ? dst_address : src_address).c_str(),
        orig_dir ? src_port : dst_port,
        orig_dir ? dst_port : src_port);
  } else {
    return StringPrintf("l3-unk-%d", l3_proto);
  }
}

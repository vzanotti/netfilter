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
#include <arpa/inet.h>

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

// Returns a string made from the @p protocol number.
string sprintf_protocol(uint8 proto) {
  if (kProtoNames[proto] == NULL) {
    return StringPrintf("l4-unk-%d", proto);
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
// Implementation of the Connection class.
//
Connection::Connection(bool conntracked)
  : conntracked_(conntracked),
    classification_mark_(Classifier::kNoMatchYet),
    packets_egress_(0), packets_ingress_(0),
    bytes_egress_(0), bytes_ingress_(0),
    buffer_egress_(), buffer_ingress_(),
    ref_counter_(1), content_lock_() {
  Acquire();
  // TODO: prepare classifier
  if (1 /* replace 1 by classifier == NULL */) {
    classification_mark_ = Classifier::kNoMatch;
  }
}

Connection::~Connection() {
  // TODO: release classifier
}

void Connection::update_packet_orig(const char* data, int32 data_len) {
  update_packet(true, data, data_len);
}

void Connection::update_packet_repl(const char* data, int32 data_len) {
  update_packet(false, data, data_len);
}

void Connection::update_packet(bool orig, const char* data, int32 data_len) {
  CHECK(data_len >= 0);

  if (orig) {
    packets_egress_++;
    bytes_egress_ += data_len;
    buffer_egress_.append(data, data_len);
  } else {
    packets_ingress_++;
    bytes_ingress_ += data_len;
    buffer_ingress_.append(data, data_len);
  }

  // TODO: update classifier !
  // TODO: shrink buffer using classifier hints.
  // TODO: switch to NO_MATCH mode if the buffer_size is above kMaxBytes.
}

Connection* Connection::get_reversed_connection() {
  Connection* conn = new Connection(conntracked_);
  conn->classification_mark_ = classification_mark_;

  conn->packets_ingress_ = conn->packets_egress_;
  conn->packets_egress_ = conn->packets_ingress_;
  conn->bytes_ingress_ = conn->bytes_egress_;
  conn->bytes_egress_ = conn->bytes_ingress_;
  conn->buffer_ingress_ = conn->buffer_egress_;
  conn->buffer_egress_ = conn->buffer_ingress_;

  return conn;
}

//
// Implementation of the ConnTrack class.
//
ConnTrack::ConnTrack() : connections_(), connections_lock_() {
  // Sets up the conntrack events listener.
  conntrack_event_handler_ = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
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

  for (map<string, Connection*>::iterator it = connections_.begin();
       it != connections_.end(); ++it)  {
    it->second->Destroy();
  }
  connections_.clear();
}

void ConnTrack::Run() {
  nfct_callback_register(conntrack_event_handler_,
                         NFCT_T_ALL,
                         ConnTrack::conntrack_callback,
                         static_cast<void*>(this));

  int result = nfct_catch(conntrack_event_handler_);
  if (result == -1) {
    LOG(FATAL, "Unable to set up the conntrack event listener (%d - %s).",
        result, strerror(errno));
  }

  if (conntrack_event_handler_) {
    nfct_close(conntrack_event_handler_);
    conntrack_event_handler_ = NULL;
  }
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
      connection = connections_[keys.first] = new Connection(false);
      direction_orig = true;
    }
  }

  return connection;
}

Connection* ConnTrack::get_connection_locked(const string& key) {
  map<string, Connection*>::iterator it = connections_.find(key);
  if (it != connections_.end()) {
    it->second->Acquire();
    return it->second;
  }
  return NULL;
}

pair<string, string> ConnTrack::get_packet_keys(const Packet& packet) {
  string l3_conntrack_orig, l3_conntrack_repl;

  if (packet.l3_protocol() == 4) {
    l3_conntrack_orig = StringPrintf(
        "src=%s dst=%s",
        sprintf_ipv4_address(packet.l3_ipv4_src()).c_str(),
        sprintf_ipv4_address(packet.l3_ipv4_dst()).c_str());
    l3_conntrack_repl = StringPrintf(
        "src=%s dst=%s",
        sprintf_ipv4_address(packet.l3_ipv4_dst()).c_str(),
        sprintf_ipv4_address(packet.l3_ipv4_src()).c_str());
  } else if (packet.l3_protocol() == 6) {
    l3_conntrack_orig = StringPrintf(
        "src=%s dst=%s",
        sprintf_ipv6_address(packet.l3_ipv6_src()).c_str(),
        sprintf_ipv6_address(packet.l3_ipv6_dst()).c_str());
    l3_conntrack_orig = StringPrintf(
        "src=%s dst=%s",
        sprintf_ipv6_address(packet.l3_ipv6_dst()).c_str(),
        sprintf_ipv6_address(packet.l3_ipv6_src()).c_str());
  } else {
    l3_conntrack_orig = StringPrintf("l3-unk-%d", packet.l3_protocol());
    l3_conntrack_repl = StringPrintf("l3-unk-%d", packet.l3_protocol());
  }

  pair<string, string> keys;
  keys.first = StringPrintf("%s %s sport=%d dport=%d",
                            sprintf_protocol(packet.l4_protocol()).c_str(),
                            l3_conntrack_orig.c_str(),
                            packet.l4_src(), packet.l4_dst());
  keys.second = StringPrintf("%s %s sport=%d dport=%d",
                             sprintf_protocol(packet.l4_protocol()).c_str(),
                             l3_conntrack_repl.c_str(),
                             packet.l4_dst(), packet.l4_src());
  return keys;
}

int ConnTrack::conntrack_callback(nf_conntrack_msg_type type,
                                  nf_conntrack* conntrack_event,
                                  void* conntrack_object) {
  ConnTrack* conntrack = reinterpret_cast<ConnTrack*>(conntrack_object);
  if (conntrack) {
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

  // Creates a new connection on new conntrack item.
  if (type == NFCT_T_NEW) {
    // TODO: checks that no connection currently exists on the reverse key.
    string key = get_conntrack_key(conntrack_event);

    WriterMutexLock ml(&connections_lock_);
    if (connections_[key] != NULL) {
      connections_[key]->set_conntracked(true);
    } else {
      connections_[key] = new Connection(true);
      connections_[key]->Release();
    }
  }

  // Deletes older connections.
  if (type == NFCT_T_DESTROY) {
    string key = get_conntrack_key(conntrack_event);

    WriterMutexLock ml(&connections_lock_);
    if (connections_[key] != NULL) {
      connections_[key]->Destroy();
      connections_.erase(key);
    }
  }

  return NFCT_CB_CONTINUE;
}

string ConnTrack::get_conntrack_key(const nf_conntrack* conntrack_event) {
  uint8 l3_proto = nfct_get_attr_u8(conntrack_event, ATTR_L3PROTO);
  string l3_conntrack;

  if (l3_proto == 4) {
    uint32 src_address = nfct_get_attr_u32(conntrack_event, ATTR_IPV4_SRC);
    uint32 dst_address = nfct_get_attr_u32(conntrack_event, ATTR_IPV4_DST);
    l3_conntrack = StringPrintf(
        "src=%s dst=%s",
        sprintf_ipv4_address(src_address).c_str(),
        sprintf_ipv4_address(dst_address).c_str());
  } else if (l3_proto == 6) {
    const void* src_address = nfct_get_attr(conntrack_event, ATTR_IPV6_SRC);
    const void* dst_address = nfct_get_attr(conntrack_event, ATTR_IPV6_DST);
    l3_conntrack = StringPrintf(
        "src=%s dst=%s",
        sprintf_ipv6_address(src_address).c_str(),
        sprintf_ipv6_address(dst_address).c_str());
  } else {
    l3_conntrack = StringPrintf("l3-unk-%d", l3_proto);
  }

  uint8 l4_proto = nfct_get_attr_u8(conntrack_event, ATTR_L4PROTO);
  uint16 src_port = nfct_get_attr_u8(conntrack_event, ATTR_PORT_SRC);
  uint16 dst_port = nfct_get_attr_u8(conntrack_event, ATTR_PORT_DST);
  return StringPrintf("%s %s sport=%d dport=%d",
                      sprintf_protocol(l4_proto).c_str(),
                      l3_conntrack.c_str(),
                      src_port, dst_port);
}




